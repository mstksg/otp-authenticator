{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeOperators       #-}

import           Authenticator
import           Control.Exception
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
import           Data.Semigroup hiding      (option)
import           Data.Singletons
import           Data.Traversable
import           Data.Type.Conjunction
import           Encrypted
import           Lens.Micro
import           Options.Applicative
import           System.Exit
import           System.FilePath
import           System.IO
import           System.IO.Error
import           System.Posix.User
import           Text.Printf
import qualified Crypto.Gpgme               as G
import qualified Data.Base32String.Default  as B32
import qualified Data.Binary                as B
import qualified Data.ByteString            as BS
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as T

data Cmd = Add Bool
         | View (Maybe T.Text) (Maybe T.Text)
         | Gen Int

data Opts = Opts { oFingerprint :: Maybe BS.ByteString
                 , oFile        :: Maybe FilePath
                 , oGPG         :: FilePath
                 , oCmd         :: Cmd
                 }

parseOpts :: Parser Opts
parseOpts = Opts <$> optional (
                       option str ( long "fingerprint"
                                 <> short 'p'
                                 <> metavar "KEY"
                                 <> help "Fingerprint of key to use"
                                  )
                                 )
                 <*> option (Just <$> str) ( long "file"
                              <> short 'f'
                              <> metavar "PATH"
                              <> value Nothing
                              <> showDefaultWith (const "~/.otp-authenticator")
                              <> help "Location of vault"
                               )
                 <*> strOption ( long "gnupg"
                              <> short 'g'
                              <> metavar "PATH"
                              <> value "~/.gnupg"
                              <> showDefaultWith id
                              <> help ".gnupg file"
                               )
                 <*> subparser ( command "add"  (info (parseAdd <**> helper)
                                                      (progDesc "Add a thing")
                                                )
                              <> command "view" (info (parseView <**> helper)
                                                      (progDesc "View the things")
                                                )
                              <> command "gen"  (info (parseGen <**> helper)
                                                      (progDesc "Generate OTP for specific item # (use view to list items)")
                                                )
                               )
  where
    parseAdd = Add <$> switch ( long "uri"
                             <> short 'u'
                             <> help "Enter account using secret URI (from QR Code)"
                              )
    parseView = View <$> optional (option str ( long "account"
                                             <> short 'a'
                                             <> metavar "NAME"
                                             <> help "Optional filter by account"
                                              )
                                  )
                     <*> optional (option str ( long "issuer"
                                             <> short 'i'
                                             <> metavar "SITE"
                                             <> help "Optional filter by issuer"
                                              )
                                  )
    parseGen = Gen <$> argument auto ( metavar "NUM"
                                    <> help "ID number of account"
                                     )

main :: IO ()
main = G.withCtx "~/.gnupg" "C" G.OpenPGP $ \ctx -> do
    Opts{..} <- execParser $ info (parseOpts <**> helper)
                                ( fullDesc
                               <> progDesc "OTP Viewer"
                               <> header "otp-authenticator: authenticate me, cap'n"
                                )
    k <- for oFingerprint $ \fing -> do
      Just k' <- G.getKey ctx fing G.NoSecret
      return k'

    oFile' <- case oFile of
      Just fp -> return fp
      Nothing -> do
        ue <- getUserEntryForID =<< getEffectiveUserID
        return $ homeDirectory ue </> ".otp-authenticator"

    e <- B.decodeFile @(Enc Store) oFile' `catch` \e ->
      if isDoesNotExistError e
        then case (,) <$> k <*> oFingerprint of
          Nothing -> do
            putStrLn "No vault found; please try again with a fingerprint to create new vault."
            exitFailure
          Just (k', fing) -> do
            printf "No vault found; generating new vault with fingerprint %s ...\n" $
              T.decodeUtf8 fing
            mkEnc ctx k' $ Store []
        else throwIO e

    e' <- case oCmd of
      View fAcc fIss -> getEnc ctx e >>= \st -> do
        _ <- flip runStateT 1 $ storeSecrets (\(sc :: Secret m) ms -> do
            i <- state $ \x -> (x :: Int, x + 1)
            fmap (fromMaybe ms) . runMaybeT $ do
              traverse_ (guard . (== secAccount sc)) fAcc
              traverse_ (guard . (== secIssuer sc) . Just) fIss
              liftIO $ case sing @_ @m of
                SHOTP ->
                  printf "(%d) %s: \tCounter-based key\n" i (describeSecret sc) $> ms
                STOTP -> do
                  p <- totp sc
                  printf "(%d) %s: %d\n" i (describeSecret sc) p
                  return ms
          ) st
        return Nothing
      Add u -> case k of
        Nothing -> do
          putStrLn "Adding a key requires a fingerprint."
          exitFailure
        Just k' -> fmap Just . overEnc ctx k' e $ \st -> do
          dsc <- if u
            then (parseSecretURI <$> query "URI Secret?") >>= \case
                    Left err -> do
                      putStrLn "Parse error:"
                      putStrLn err
                      exitFailure
                    Right d ->
                      return d
            else mkSecret
          putStrLn "Added succesfully!"
          return $
            st & _Store %~ (++ [dsc])
      Gen n -> getEnc ctx e >>= \st -> do
        (new, (changed, found)) <- runWriterT . flip evalStateT 1 $ storeSecrets (\(sc :: Secret m) ms -> do
            i <- state $ \x -> (x :: Int, x + 1)
            if n == i
              then case sing @_ @m of
                SHOTP -> do
                  let (p, ms') = hotp sc ms
                  liftIO $ printf "(%d) %s: %d\n" i (describeSecret sc) p
                  lift $ ms' <$ tell (Any True, Any True)
                STOTP -> do
                  liftIO $ do
                    p <- totp sc
                    printf "(%d) %s: %d\n" i (describeSecret sc) p
                  lift $ ms <$ tell (Any False, Any True)
              else return ms
          ) st
        if getAny found
          then if getAny changed
                 then Just <$> mkEnc ctx undefined new
                 else return Nothing
          else do
            printf "No item with ID %d found.\n" n
            exitFailure

    traverse_ (B.encodeFile oFile') e'

mkSecret :: IO (DSum Sing (Secret :&: ModeState))
mkSecret = do
    a <- query "Account?"
    i <- query "Issuer? (optional)"
    k <- query "Secret?"
    m <- query "(t)ime- or (c)ounter-based?"
    let i' = mfilter (not . null) (Just i)
        k' = B32.toBytes . B32.b32String' . T.encodeUtf8
           . T.pack
           . filter isAlphaNum
           $ k
        s  = Sec (T.pack a)
                 (T.pack <$> i')
                 HASHA1
                 6
                 k'
    case m of
      'c':_ -> do
        n <- query "Initial counter?"
        let n' | null n    = 0
               | otherwise = read n
        return $ SHOTP :=> s :&: HOTPState n'
      't':_ -> return $ STOTP :=> s :&: TOTPState
      _     -> error "Unknown type"

query :: String -> IO String
query p = do
    putStr $ p ++ ": "
    hFlush stdout
    getLine
