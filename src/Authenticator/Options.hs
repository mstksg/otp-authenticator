{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE LambdaCase      #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections   #-}

module Authenticator.Options (
    Cmd(..)
  , DumpType(..)
  , getOptions
  ) where

import           Authenticator.Common
import           Control.Exception
import           Control.Monad
import           Data.Functor
import           Data.Maybe
import           Data.Monoid
import           Data.String
import           GHC.Generics                  (Generic)
import           Options.Applicative hiding    (str)
import           Prelude hiding                (filter)
import           System.FilePath
import           System.IO.Error
import           System.Posix.User
import           Text.Printf
import qualified Crypto.Gpgme                  as G
import qualified Data.Aeson                    as J
import qualified Data.Aeson.Types              as J
import qualified Data.ByteString               as BS
import qualified Data.Text                     as T
import qualified Data.Text.Encoding            as T
import qualified Data.Yaml                     as Y
import qualified Options.Applicative           as O


data DumpType = DTYaml | DTJSON

data Cmd = Add Bool
         | View Bool (Either Int (Maybe T.Text, Maybe T.Text))
         | Gen Int
         | Edit Int
         | Delete Int
         | Dump DumpType

data Opts = Opts { oFingerprint :: Maybe BS.ByteString
                 , oVault       :: Maybe FilePath
                 , oConfig      :: Maybe FilePath
                 , oGPG         :: FilePath
                 , oCmd         :: Cmd
                 }

data Config = Conf { cFingerprint :: Maybe T.Text
                   , cVault       :: Maybe FilePath
                   }
  deriving (Generic)

confJsonOpts :: J.Options
confJsonOpts = J.defaultOptions { J.fieldLabelModifier = J.camelTo2 '-' . drop 1 }
instance J.FromJSON Config where
    parseJSON  = J.genericParseJSON  confJsonOpts
instance J.ToJSON Config where
    toEncoding = J.genericToEncoding confJsonOpts
    toJSON     = J.genericToJSON     confJsonOpts

parseOpts :: Parser Opts
parseOpts = Opts <$> optional (
                       option str ( long "fingerprint"
                                 <> short 'p'
                                 <> metavar "KEY"
                                 <> help "Fingerprint of key to use"
                                  )
                                 )
                 <*> option (Just <$> str) ( long "vault"
                              <> short 'v'
                              <> metavar "PATH"
                              <> value Nothing
                              <> showDefaultWith (const "~/.otp-auth.vault")
                              <> help "Location of vault"
                               )
                 <*> option (Just <$> str) ( long "config"
                              <> short 'c'
                              <> metavar "PATH"
                              <> value Nothing
                              <> showDefaultWith (const "~/.otp-auth.yaml")
                              <> help "Location of configuration file"
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

-- | Return command, vault filepath, and fingerprint
getOptions :: IO (Cmd, FilePath, Maybe G.Fpr)
getOptions = do
    Opts{..} <- execParser $ info (parseOpts <**> helper)
                                ( fullDesc
                               <> progDesc "OTP Viewer"
                               <> header "otp-authenticator: authenticate me, cap'n"
                                )

    oConfig' <- case oConfig of
      Just fp -> return fp
      Nothing -> do
        ue <- getUserEntryForID =<< getEffectiveUserID
        return $ homeDirectory ue </> ".otp-auth.yaml"

    (Conf{..}, mkNewConf) <- do
      (c0, mkNew) <- ((, False) . Y.decodeEither <$> BS.readFile oConfig') `catch` \e ->
        if isDoesNotExistError e
          then return (Right (Conf Nothing Nothing), True)
          else throwIO e
      case c0 of
        Left e -> do
          putStrLn "Could not parse configuration file.  Ignoring."
          putStrLn e
          return (Conf Nothing Nothing, False)
        Right c1 -> return (c1, mkNew)

    vault <- case oVault <|> cVault of
      Just fp -> return fp
      Nothing -> do
        ue <- getUserEntryForID =<< getEffectiveUserID
        return $ homeDirectory ue </> ".otp-auth.vault"


    cFingerprint' <- if mkNewConf
      then do
        printf "Config file not found; generating default file at %s\n" oConfig'
        fing <- case oFingerprint of
          Just p  -> return $ Just (T.decodeUtf8 p)
          Nothing -> mfilter (not . T.null) . Just . T.pack <$> query "Fingerprint?"
        Y.encodeFile oConfig' $ Conf fing (Just vault)
        return fing
      else
        return cFingerprint

    let fingerprint = oFingerprint <|> (T.encodeUtf8 <$> cFingerprint')

    return (oCmd, vault, fingerprint)

-- | is str from optparse-applicative 0.14 and above
str :: IsString s => ReadM s
str = fromString <$> O.str
