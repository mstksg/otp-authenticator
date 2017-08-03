{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}

import           Authenticator
import           Control.Exception
import           Control.Monad
import           Data.Char
import           Data.Dependent.Sum
import           Data.Functor
import           Data.Semigroup hiding     (option)
import           Data.Singletons
import           Data.Type.Conjunction
import           Encrypted
import           Lens.Micro
import           Options.Applicative
import           System.FilePath
import           System.IO
import           System.IO.Error
import           System.Posix.User
import           Text.Printf
import qualified Crypto.Gpgme              as G
import qualified Data.Base32String.Default as B32
import qualified Data.Binary               as B
import qualified Data.ByteString           as BS
import qualified Data.Text                 as T
import qualified Data.Text.Encoding        as T

data Cmd = Add
         | View

data Opts = Opts { oFingerprint :: BS.ByteString
                 , oFile        :: Maybe FilePath
                 , oGPG         :: FilePath
                 , oCmd         :: Cmd
                 }

parseOpts :: Parser Opts
parseOpts = Opts <$> option str ( long "fingerprint"
                               <> short 'p'
                               <> metavar "KEY"
                               <> help "Fingerprint of key to use"
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
                 <*> subparser ( command "add" (info parseAdd (progDesc "Add a thing"))
                              <> command "view" (info parseView (progDesc "View a thing"))
                               )
  where
    parseAdd = pure Add
    parseView = pure View

main :: IO ()
main = G.withCtx "~/.gnupg" "C" G.OpenPGP $ \ctx -> do
    Opts{..} <- execParser $ info (parseOpts <**> helper)
                                ( fullDesc
                               <> progDesc "OTP Viewer"
                               <> header "otp-authenticator: authenticate me, cap'n"
                                )
    Just k <- G.getKey ctx oFingerprint G.NoSecret

    oFile' <- case oFile of
      Just fp -> return fp
      Nothing -> do
        ue <- getUserEntryForID =<< getEffectiveUserID
        return $ homeDirectory ue </> ".otp-authenticator"

    e <- B.decodeFile @(Enc Store) oFile' `catch` \e ->
      if isDoesNotExistError e
        then do
          putStrLn "Generating new vault ..."
          mkEnc ctx k $ Store []
        else throwIO e
    
    e' <- overEnc ctx k e $ \st ->
      case oCmd of
        View -> storeSecrets (\(sc :: Secret m) ms -> do
            case sing @_ @m of
              SHOTP -> printf "%s: \tCounter-based key\n" (describeSecret sc) $> ms
              STOTP -> do
                p <- totp sc
                printf "%s: %d\n" (describeSecret sc) p
                return ms
          ) st
        Add -> do
          dsc <- mkSecret
          return $ case dsc of
            s :=> sc -> withSingI s $
              st & _Store %~ (++ [s :=> (sc :&: initState)])

    B.encodeFile oFile' e'
  where
    -- is there a lib for this?
    -- expandHome :: FilePath -> IO FilePath
    -- expandHome = \case
    --   '~':s -> do
    --     let (uname, rest) = span (/= '/') s
    --     ue <- if null uname
    --       then getUserEntryForID =<< getEffectiveUserID
    --       else getUserEntryForName uname
    --     return $ homeDirectory ue ++ rest
    --   fp -> return fp

    -- e <- mkEnc ctx k ("Hello, world!" :: String)
    -- B.encodeFile "enctest.dat" e
    -- e' <- B.decodeFile @(Enc String) "enctest.dat"
    -- putStrLn =<< getEnc ctx e'

mkSecret :: IO (DSum Sing Secret)
mkSecret = do
    a <- putStr "Account?: " *> hFlush stdout *> getLine
    i <- putStr "Issuer?: " *> hFlush stdout *> getLine
    k <- putStr "Secret?: " *> hFlush stdout *> getLine
    m <- putStr "(t)ime- or (c)ounter-based?: " *> hFlush stdout *> getLine
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
    return $ case m of
      'c':_ -> SHOTP :=> s
      't':_ -> STOTP :=> s
      _     -> error "Unknown type"

