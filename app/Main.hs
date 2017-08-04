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
import           Data.Monoid                (First(..))
import           Data.Semigroup hiding      (option, First(..))
import           Data.Singletons
import           Data.Traversable
import           Data.Type.Conjunction
import           Data.Witherable
import           Encrypted
import           Lens.Micro
import           Options.Applicative
import           Prelude hiding             (filter)
import           System.Exit
import           System.FilePath
import           System.IO
import           System.IO.Error
import           System.Posix.User
import           Text.Printf
import           Text.Read                  (readMaybe)
import qualified Crypto.Gpgme               as G
import qualified Data.Aeson                 as J
import qualified Data.Base32String.Default  as B32
import qualified Data.Binary                as B
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Lazy       as BSL
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as T
import qualified Data.Text.IO               as T
import qualified Data.Yaml                  as Y

data DumpType = DTYaml | DTJSON

data Cmd = Add Bool
         | View Bool (Either Int (Maybe T.Text, Maybe T.Text))
         | Gen Int
         | Edit Int
         | Delete Int
         | Dump DumpType

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
                              <> command "edit" (info (parseEdit <**> helper)
                                                      (progDesc "Edit a thing")
                                                )
                              <> command "delete" (info (parseDelete <**> helper)
                                                      (progDesc "Delete a thing")
                                                )
                              <> command "dump" (info (parseDump <**> helper)
                                                      (progDesc "Dump all data as json")
                                                )
                               )
  where
    parseAdd = Add <$> switch ( long "uri"
                             <> short 'u'
                             <> help "Enter account using secret URI (from QR Code)"
                              )
    parseView = View <$> switch ( long "list"
                               <> short 'l'
                               <> help "Only list accounts; do not generate any keys."
                                )
                     <*> (Left <$> (argument auto ( metavar "ID"
                                                   <> help "Specific ID number of account"
                                                   ))
                       <|> Right <$> ((,) <$> optional (option str ( long "account"
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
                                             ))
                          )
    parseGen = Gen <$> argument auto ( metavar "ID"
                                    <> help "ID number of account"
                                     )
    parseEdit = Edit <$> argument auto ( metavar "ID"
                                      <> help "ID number of account"
                                       )
    parseDelete = Delete <$> argument auto ( metavar "ID"
                                      <> help "ID number of account"
                                       )
    parseDump = Dump <$> flag DTJSON DTYaml ( long "yaml"
                                           <> short 'y'
                                           <> help "Yaml output"
                                            )

main :: IO ()
main = G.withCtx "~/.gnupg" "C" G.OpenPGP $ \ctx -> do
    Opts{..} <- execParser $ info (parseOpts <**> helper)
                                ( fullDesc
                               <> progDesc "OTP Viewer"
                               <> header "otp-authenticator: authenticate me, cap'n"
                                )
    k <- for oFingerprint $ \fing -> do
      G.getKey ctx fing G.NoSecret >>= \case
        Nothing -> do
          printf "No key found for fingerprint %s!\n" (T.decodeUtf8 fing)
          exitFailure
        Just k' -> return k'

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
      View l filts -> getEnc ctx e >>= \st -> do
        (n,found) <- runWriterT . flip execStateT 1 $ storeSecrets (\(sc :: Secret m) ms -> do
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
                else case sing @_ @m of
                  SHOTP -> ms <$ case hotpLast ms of
                    Nothing -> printf "(%d) %s: [ counter-based, unitialized ]\n" i (describeSecret sc)
                    Just p  -> printf "(%d) %s: %d **\n" i (describeSecret sc) p
                  STOTP -> do
                    p <- totp sc
                    printf "(%d) %s: %d\n" i (describeSecret sc) p
                    return ms
          ) st
        printf "Searched %d total entries.\n" (n - 1)
        unless (getAny found) $ case filts of
          Left i   -> printf "ID %d not found!\n" i *> exitFailure
          Right _  -> putStrLn "No matches found!"
        return Nothing
      Add u -> case k of
        Nothing -> do
          putStrLn "Adding a key requires a fingerprint."
          exitFailure
        Just k' -> fmap Just . overEnc ctx k' e $ \st -> do
          -- TODO: veriffy
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
        res <- runMaybeT . runWriterT . flip evalStateT 1 $ storeSecrets (\(sc :: Secret m) ms -> do
            i <- state $ \x -> (x :: Int, x + 1)
            if n == i
              then case sing @_ @m of
                SHOTP -> case k of
                  Just k' -> do
                    let (p, ms') = hotp sc ms
                    liftIO $ printf "(%d) %s: %d\n" i (describeSecret sc) p
                    lift $ ms' <$ tell (First (Just k'))
                  Nothing -> liftIO $ do
                    putStrLn "Generating a counter-based (HOTP) key requires a fingerprint."
                    exitFailure
                STOTP -> do
                  liftIO $ do
                    p <- totp sc
                    printf "(%d) %s: %d\n" i (describeSecret sc) p
                  empty
              else return ms
          ) st
        forM res $ \(r, changed) ->
          case getFirst changed of
            Just k' -> mkEnc ctx k' r
            Nothing -> do
              printf "No item with ID %d found.\n" n
              exitFailure
      Edit n -> case k of
        Nothing -> do
          putStrLn "Editing keys requires a fingerprint."
          exitFailure
        Just k' -> fmap Just . overEnc ctx k' e $ \st -> do
          (st', found) <- runWriterT . flip evalStateT 1 . forOf (_Store . traverse) st $ \case
            ds@(s :=> sc :&: ms) -> do
              i <- state $ \x -> (x :: Int, x + 1)
              if n == i
                then do
                  sc' <- liftIO $ do
                    printf "Editing (%d) %s ...\n" i (describeSecret sc)
                    liftIO (editSecret sc)
                  lift $ tell (First (Just (describeSecret sc')))
                  return $ s :=> sc :&: ms
                else return ds
          case getFirst found of
            Nothing -> do
              printf "No item with ID %d found.\n" n
              exitFailure
            Just desc -> do
              printf "%s edited successfuly!\n" desc
              return st'
      Delete n -> case k of
        Nothing -> do
          putStrLn "Deleting keys requires a fingerprint."
          exitFailure
        Just k' -> fmap Just . overEnc ctx k' e $ \st -> do
          (st', found) <- runWriterT . flip evalStateT 1 . forOf (_Store . wither) st $ \case
            ds@(_ :=> sc :&: _) -> do
              i <- state $ \x -> (x :: Int, x + 1)
              if n == i
                then do
                  a <- liftIO . query $ printf "Delete %s? y/[n]" (describeSecret sc)
                  case unwords . words . map toLower $ a of
                    'y':_ -> do
                      liftIO $ putStrLn "Deleted!"
                      lift $ tell (Any True)
                      return Nothing
                    _     -> return (Just ds)
                else return (Just ds)
          unless (getAny found) $ do
            printf "No item with ID %d found.\n" n
            exitFailure
          return st'
      Dump t -> getEnc ctx e >>= \st -> do
        T.putStrLn . T.decodeUtf8 $ case t of
            DTJSON -> BSL.toStrict $ J.encode st
            DTYaml -> Y.encode st
        return Nothing

    traverse_ (B.encodeFile oFile') e'

mkSecret :: IO (DSum Sing (Secret :&: ModeState))
mkSecret = do
    a <- query "Account?"
    i <- query "Issuer? (optional)"
    k <- query "Secret?"
    m <- query "[t]ime- or (c)ounter-based?"
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
        n <- query "Initial counter? [0]"
        n' <- if null n
          then return 0
          else case readMaybe n of
                 Just r -> return r
                 Nothing -> putStrLn "Invalid initial counter.  Using 0." $> 0
        return $ SHOTP :=> s :&: HOTPState n' Nothing
      't':_ -> return $ STOTP :=> s :&: TOTPState
      _     -> error "Unknown type"

editSecret :: Secret m -> IO (Secret m)
editSecret sc = do
    a <- query $ printf "Account? [%s]" (secAccount sc)
    i <- query $ printf "Issuer?%s (optional)" (case secIssuer sc of
                                                  Nothing -> ""
                                                  Just si -> " [" <> si <> "]"
                                               )
    let a' | null a    = secAccount sc
           | otherwise = T.pack a
        i' | null i    = secIssuer sc
           | otherwise = Just $ T.pack i
    return $ sc { secAccount = a'
                , secIssuer  = i'
                }

query :: String -> IO String
query p = do
    putStr $ p ++ ": "
    hFlush stdout
    getLine
