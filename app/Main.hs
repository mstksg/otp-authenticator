{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

import Authenticator.Actions
import Authenticator.Options
import Authenticator.Vault
import Control.Exception
import Control.Monad
import qualified Crypto.Gpgme as G
import qualified Data.Aeson as J
import qualified Data.Binary as B
import qualified Data.ByteString.Lazy as BSL
import Data.Functor
import Data.Maybe
import qualified Data.Text.Encoding as T
import qualified Data.Text.IO as T
import Data.Traversable
import qualified Data.Yaml as Y
import Encrypted
import System.Exit
import System.IO.Error
import Text.Printf
import Prelude hiding (filter)

main :: IO ()
main = G.withCtx "~/.gnupg" "C" G.OpenPGP $ \ctx -> do
  (cmd, echoPass, vault, fingerprint) <- getOptions

  k <- for fingerprint $ \fing ->
    G.getKey ctx fing G.NoSecret >>= \case
      Nothing -> do
        printf "No key found for fingerprint %s!\n" (T.decodeUtf8 fing)
        exitFailure
      Just k' -> return k'

  (e, mkNewVault) <-
    ((,False) <$> B.decodeFile @(Enc Vault) vault) `catch` \e ->
      if isDoesNotExistError e
        then case (,) <$> k <*> fingerprint of
          Nothing -> do
            putStrLn "No vault found; please try again with a fingerprint to create new vault."
            exitFailure
          Just (k', fing) -> do
            printf "No vault found; generating new vault with fingerprint %s ...\n" $
              T.decodeUtf8 fing
            (,True) <$> mkEnc ctx k' (Vault [])
        else throwIO e

  e' <- case cmd of
    View l j filts -> (Nothing <$) . viewVault l j filts =<< getEnc ctx e
    Add u -> case k of
      Nothing -> do
        putStrLn "Adding a key requires a fingerprint."
        exitFailure
      Just k' -> Just <$> overEnc ctx k' e (addSecret echoPass u)
    Gen n -> do
      vtmsg <- genSecret n =<< getEnc ctx e
      forM vtmsg $ \(s, vt) -> case k of
        Nothing -> do
          putStrLn "Generating a counter-based (HOTP) key requires a fingerprint."
          exitFailure
        Just k' -> do
          putStrLn s
          mkEnc ctx k' vt
    Edit n -> case k of
      Nothing -> do
        putStrLn "Editing keys requires a fingerprint."
        exitFailure
      Just k' -> Just <$> overEnc ctx k' e (editSecret n)
    Delete n -> case k of
      Nothing -> do
        putStrLn "Deleting keys requires a fingerprint."
        exitFailure
      Just k' -> Just <$> overEnc ctx k' e (deleteSecret n)
    Dump t ->
      getEnc ctx e >>= \vt -> do
        T.putStrLn . T.decodeUtf8 $ case t of
          DTJSON -> BSL.toStrict $ J.encode vt
          DTYaml -> Y.encode vt
        return Nothing

  case e' of
    Just changed -> B.encodeFile vault changed
    Nothing
      | mkNewVault -> B.encodeFile vault e
      | otherwise -> return ()
