{-# LANGUAGE GADTs               #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators       #-}

-- |
-- Module      : Authenticator.Actions
-- Description : Simple CLI actions for 'Vault's.
-- Copyright   : (c) Justin Le 2017
-- License     : MIT
-- Maintainer  : justin@jle.im
-- Stability   : unstable
-- Portability : portable
--
-- Basic actions to manipulate 'Vault's.  The @otp-auth@ executable is
-- a thin wrapper over these actions.
--
-- See 'Cmd'.
--


module Authenticator.Actions (
    viewVault
  , addSecret
  , genSecret
  , editSecret
  , deleteSecret
  ) where

import           Authenticator.Common
import           Authenticator.Vault
import           Control.Monad
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Class
import           Control.Monad.Trans.Maybe
import           Control.Monad.Trans.State
import           Control.Monad.Trans.Writer
import           Data.Char
import           Data.Dependent.Sum
import           Data.Foldable
import           Data.Functor
import           Data.Maybe
import           Data.Monoid
import           Data.String
import           GHC.Generics
import           Lens.Micro
import           Options.Applicative
import           Prelude hiding             (filter)
import           System.Exit
import           Text.Printf
import           Text.Read                  (readMaybe)
import qualified Crypto.OTP                 as OTP
import qualified Data.Text                  as T
import qualified System.Console.Haskeline   as L

-- | View secrets, generating codes for time-based keys.
viewVault
    :: Bool                                     -- ^ List key names only; do not generate any codes.
    -> Either Int (Maybe T.Text, Maybe T.Text)  -- ^ Filter by ID or possibly by account name and issuer
    -> Vault
    -> IO ()
viewVault l filts vt = do
    (n,found) <- runWriterT . (`execStateT` 1) $ (`vaultSecrets` vt) $ \m sc ms -> do
        i <- state $ \x -> (x :: Int, x + 1)
        fmap (fromMaybe ms) . runMaybeT $ do
          case filts of
            Left n -> guard (i == n)
            Right (fAcc, fIss) -> do
              traverse_ (guard . (== secAccount sc)) fAcc
              traverse_ (guard . (== secIssuer sc) . Just) fIss
          lift . lift $ tell (Any True)
          liftIO $ if l
            then printf "(%d) %s\n" i (describeSecret sc) $> ms
            else case m of
              SHOTP -> ms <$
                printf "(%d) %s: [ counter-based, use gen ]\n" i (describeSecret sc)
              STOTP -> do
                p <- totp sc
                printf "(%d) %s: %s\n" i (describeSecret sc) p
                return ms
    printf "Searched %d total entries.\n" (n - 1)
    unless (getAny found) $ case filts of
      Left i   -> printf "ID %d not found!\n" i *> exitFailure
      Right _  -> putStrLn "No matches found!"

-- | Add a secret, interactively.
addSecret
    :: Bool         -- ^ Echo back password entry
    -> Bool         -- ^ If 'True', add via otpauth protocol URI
    -> Vault
    -> IO Vault
addSecret echoPass u vt = do
    -- TODO: verify b32?
    dsc <- if u
      then do
        q <- L.runInputT hlSettings $
          fromMaybe "" <$> if echoPass
                             then L.getInputLine "URI Secret?: "
                             else L.getPassword (Just '*') "URI Secret?: "
        putStrLn "parsing"
        case parseSecretURI q of
          Left err -> do
            putStrLn "Parse error:"
            putStrLn err
            exitFailure
          Right d ->
            return d
      else mkSecret echoPass
    putStrLn "Added succesfully!"
    return $
      vt & _Vault %~ (++ [dsc])

-- | Generate a secret code, forcing a new HOTP code if it is
-- counter-based.
genSecret
    :: Int      -- ^ ID # of secret to generate
    -> Vault
    -> IO (Maybe (String, Vault))
genSecret n vt = do
    res <- runMaybeT . runWriterT . forOf (_Vault . ix (n - 1)) vt $ \case
      s :=> sc :*: ms ->
        case s of
          SHOTP -> do
            let (p, ms') = hotp sc ms
                out = printf "(%d) %s: %s\n" n (describeSecret sc) p
            tell (First (Just out))
            return $ s :=> sc :*: ms'
          STOTP -> do
            liftIO $ do
              p <- totp sc
              printf "(%d) %s: %s\n" n (describeSecret sc) p
            empty
    forM res $ \(r, changed) ->
      case getFirst changed of
        Just msg -> return (msg, r)
        Nothing -> do
          printf "No item with ID %d found.\n" n
          exitFailure

-- | Edit a secret's metadata (account name, issuer)
editSecret
    :: Int      -- ^ ID # of secret to edit
    -> Vault
    -> IO Vault
editSecret n vt = do
    (vt', found) <- runWriterT . forOf (_Vault . ix (n - 1)) vt $ \case
      (s :=> sc :*: ms) -> do
        sc' <- liftIO $ do
          printf "Editing (%d) %s ...\n" n (describeSecret sc)
          liftIO (mkSecretFrom sc)
        tell (First (Just (describeSecret sc')))
        return $ s :=> sc' :*: ms
    case getFirst found of
      Nothing -> do
        printf "No item with ID %d found.\n" n
        exitFailure
      Just desc -> do
        printf "%s edited successfuly!\n" desc
        return vt'

-- | Delete a secret.
deleteSecret
    :: Int          -- ^ ID # of secret to delete
    -> Vault
    -> IO Vault
deleteSecret n vt = do
    (vt', found) <- runWriterT . flip evalStateT 1 . forOf (_Vault . wither) vt $ \case
      ds@(_ :=> sc :*: _) -> do
        i <- state $ \x -> (x :: Int, x + 1)
        if n == i
          then do
            lift $ tell (Any True)
            a <- liftIO . L.runInputT hlSettings $
                L.getInputChar (printf "Delete %s? y/[n]: " (describeSecret sc))
            case toLower <$> a of
              Just 'y' -> do
                liftIO $ putStrLn "Deleted!"
                return Nothing
              _     -> return (Just ds)
          else return (Just ds)
    unless (getAny found) $ do
      printf "No item with ID %d found.\n" n
      exitFailure
    return vt'
  where
    wither f = fmap catMaybes . traverse f

mkSecret :: Bool -> IO SomeSecretState
mkSecret echoPass = L.runInputT hlSettings $ do
    a <- (mfilter (not . null) <$> L.getInputLine "Account?: ") >>= \case
      Nothing -> liftIO $ putStrLn "Account required" >> exitFailure
      Just r  -> return r
    i <- L.getInputLine "Issuer? (optional): "
    k <- fromMaybe "" <$> if echoPass
                            then L.getInputLine "Secret?: "
                            else L.getPassword (Just '*') "Secret?: "
    m <- L.getInputChar "[t]ime- or (c)ounter-based?: "
    let i' = mfilter (not . null) i
        k' = decodePad . T.pack $ k
        s :: Maybe (Secret m)
        s  = Sec (T.pack a) (T.pack <$> i') HASHA1 (OTPDigits OTP.OTP6) <$> k'
    case toLower <$> m of
      Just 'c' -> do
        n <- mfilter (not . null) <$> L.getInputLine "Initial counter? [0]: "
        n' <- case n of
          Nothing -> return 0
          Just n' -> case readMaybe n' of
            Just r -> return r
            Nothing -> liftIO $ putStrLn "Invalid initial counter.  Using 0." $> 0
        case s of
          Nothing -> liftIO $ do
            printf "Invalid secret key: %s\n" k
            exitFailure
          Just s' -> return $ SHOTP :=> s' :*: HOTPState n'
      _ -> case s of
        Nothing -> liftIO $ do
          printf "Invalid secret key: %s\n" k
          exitFailure
        Just s' -> return $ STOTP :=> (s' :*: TOTPState)

mkSecretFrom :: Secret m -> IO (Secret m)
mkSecretFrom sc = L.runInputT hlSettings $ do
    a <- mfilter (not . null) <$> L.getInputLineWithInitial "Account?: " (T.unpack (secAccount sc), "")
    i <- mfilter (not . null) <$> case secIssuer sc of
           Nothing -> L.getInputLine "Issuer? (optional): "
           Just si -> L.getInputLineWithInitial "Issuer? (optional): " (T.unpack si, "")
    let a' = case a of
               Nothing -> secAccount sc
               Just r  -> T.pack r
        i' = case i of
               Nothing -> secIssuer sc
               Just r  -> Just $ T.pack r
    return $ sc { secAccount = a'
                , secIssuer  = i'
                }
