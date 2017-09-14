{-# LANGUAGE DeriveFunctor        #-}
{-# LANGUAGE DeriveGeneric        #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE GADTs                #-}
{-# LANGUAGE KindSignatures       #-}
{-# LANGUAGE LambdaCase           #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE RankNTypes           #-}
{-# LANGUAGE RecordWildCards      #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE StandaloneDeriving   #-}
{-# LANGUAGE TemplateHaskell      #-}
{-# LANGUAGE TupleSections        #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeInType           #-}
{-# LANGUAGE TypeOperators        #-}
{-# LANGUAGE ViewPatterns         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- |
-- Module      : Authenticator.Vault
-- Description : Secrets and storage for OTP keys.
-- Copyright   : (c) Justin Le 2017
-- License     : MIT
-- Maintainer  : justin@jle.im
-- Stability   : unstable
-- Portability : portable
--
-- Types for storing, serializing, accessing OTP keys.  Gratuitous
-- type-level programming here for no reason because I have issues.
--
-- Based off of <https://github.com/google/google-authenticator>.
--


module Authenticator.Vault (
    Mode(..)
  , Sing(SHOTP, STOTP)
  , SMode, HOTPSym0, TOTPSym0
  , HashAlgo(..)
  , parseAlgo
  , Secret(..)
  , ModeState(..)
  , SomeSecretState
  , Vault(..)
  , _Vault
  , hotp
  , totp
  , totp_
  , otp
  , someSecret
  , vaultSecrets
  , describeSecret
  , secretURI
  , parseSecretURI
  ) where

import           Authenticator.Common
import           Control.Applicative
import           Control.Monad
import           Crypto.Hash.Algorithms
import           Data.Bitraversable
import           Data.Char
import           Data.Dependent.Sum
import           Data.Kind
import           Data.Maybe
import           Data.Semigroup
import           Data.Singletons
import           Data.Singletons.TH
import           Data.Time.Clock
import           Data.Type.Combinator
import           Data.Type.Conjunction
import           Data.Word
import           GHC.Generics           (Generic)
import           Text.Printf
import           Text.Read              (readMaybe)
import           Type.Class.Higher
import           Type.Class.Witness
import qualified Codec.Binary.Base32    as B32
import qualified Data.Aeson             as J
import qualified Data.Binary            as B
import qualified Data.ByteString        as BS
import qualified Data.Map               as M
import qualified Data.OTP               as OTP
import qualified Data.Text              as T
import qualified Data.Text.Encoding     as T
import qualified Network.URI.Encode     as U
import qualified Text.Trifecta          as P

-- | OTP generation mode
data Mode
    -- | Counter-based
    = HOTP
    -- | Time-based
    | TOTP
  deriving (Generic, Show)

genSingletons [''Mode]

instance B.Binary Mode
instance J.ToJSON Mode where
    toJSON HOTP = J.toJSON @T.Text "hotp"
    toJSON TOTP = J.toJSON @T.Text "totp"

-- | A data family consisting of the state required by each mode.
data family ModeState :: Mode -> Type

-- | For 'HOTP' (counter-based) mode, the state is the current counter.
data instance ModeState 'HOTP = HOTPState { hotpCounter :: Word64 }
  deriving (Generic, Show)

-- | For 'TOTP' (time-based) mode, there is no state.
data instance ModeState 'TOTP = TOTPState
  deriving (Generic, Show)

instance B.Binary (ModeState 'HOTP)
instance B.Binary (ModeState 'TOTP)
instance J.ToJSON (ModeState 'HOTP) where
    toEncoding (HOTPState{..}) = J.pairs $ "counter" J..= hotpCounter
    toJSON (HOTPState{..}) = J.object
      [ "counter" J..= hotpCounter ]

instance J.ToJSON (ModeState 'TOTP)

modeStateBinary :: Sing m -> Wit1 B.Binary (ModeState m)
modeStateBinary = \case
    SHOTP -> Wit1
    STOTP -> Wit1

-- | Which OTP-approved hash algorithm to use?
data HashAlgo = HASHA1 | HASHA256 | HASHA512
  deriving (Generic, Show)

instance B.Binary HashAlgo
instance J.ToJSON HashAlgo where
    toJSON HASHA1   = J.toJSON @T.Text "sha1"
    toJSON HASHA256 = J.toJSON @T.Text "sha256"
    toJSON HASHA512 = J.toJSON @T.Text "sha512"

-- | Generate the /cryptonite/ 'HashAlgorithm' instance.
hashAlgo :: HashAlgo -> SomeC HashAlgorithm I
hashAlgo HASHA1   = SomeC (I SHA1  )
hashAlgo HASHA256 = SomeC (I SHA256)
hashAlgo HASHA512 = SomeC (I SHA512)

-- | Parse a hash algorithm string into the appropriate 'HashAlgo'.
parseAlgo :: String -> Maybe HashAlgo
parseAlgo = (`lookup` algos) . map toLower . unwords . words
  where
    algos = [("sha1", HASHA1)
            ,("sha256", HASHA256)
            ,("sha512", HASHA512)
            ]

-- | A standards-compliant secret key type.  Well, almost.  It doesn't
-- include configuration for the time period if it's time-based.
data Secret :: Mode -> Type where
    Sec :: { secAccount :: T.Text
           , secIssuer  :: Maybe T.Text
           , secAlgo    :: HashAlgo
           , secDigits  :: Word
           , secKey     :: BS.ByteString
           }
        -> Secret m
  deriving (Generic, Show)

instance B.Binary (Secret m)
instance J.ToJSON (Secret m) where
    toEncoding (Sec{..}) = J.pairs
        ( "account"   J..= secAccount
       <> maybe mempty ("issuer" J..=) secIssuer
       <> "algorithm" J..= secAlgo
       <> "digits"    J..= secDigits
       <> "key"       J..= formatKey 4 (T.decodeUtf8 (B32.encode secKey))
        )
    toJSON (Sec{..}) = J.object $
        [ "account"   J..= secAccount
        , "algorithm" J..= secAlgo
        , "digits"    J..= secDigits
        , "key"       J..= formatKey 4 (T.decodeUtf8 (B32.encode secKey))
        ] ++ maybe [] ((:[]) . ("issuer" J..=)) secIssuer

formatKey
    :: Int      -- ^ chunk size
    -> T.Text
    -> T.Text
formatKey c = T.unwords
          . T.chunksOf c
          . T.map toLower
          . T.filter isAlphaNum

-- | Print out the metadata (account name and issuer) of a 'Secret'.
describeSecret
    :: Secret m
    -> T.Text
describeSecret s = secAccount s <> case secIssuer s of
                                     Nothing -> ""
                                     Just i  -> " / " <> i

instance B.Binary SomeSecretState where
    get = do
      m <- B.get
      withSomeSing m $ \s -> modeStateBinary s // do
        sc <- B.get
        ms <- B.get
        return $ s :=> sc :&: ms
    put = \case
      s :=> sc :&: ms -> modeStateBinary s // do
        B.put $ fromSing s
        B.put sc
        B.put ms

instance J.ToJSON SomeSecretState where
    toEncoding (s :=> sc :&: ms) = J.pairs
        ( "type"   J..= fromSing s
       <> "secret" J..= sc
       <> (case s of SHOTP -> "state" J..= ms
                     STOTP -> mempty
          )
        )
    toJSON (s :=> sc :&: ms) = J.object $
        [ "type"   J..= fromSing s
        , "secret" J..= sc
        ] ++ case s of SHOTP -> ["state" J..= ms]
                       STOTP -> []

-- | A 'Secret' coupled with its 'ModeState', existentially quantified over
-- its 'Mode'.
type SomeSecretState = DSum SMode (Secret :&: ModeState)

-- | A list of secrets and their states, of various modes.
data Vault = Vault { vaultList :: [SomeSecretState] }
  deriving Generic

instance B.Binary Vault
instance J.ToJSON Vault where
    toEncoding l = J.pairs $ "vault" J..= vaultList l
    toJSON l     = J.object ["vault" J..= vaultList l]

-- | Generate an HTOP (counter-based) code, returning a modified state.
hotp :: Secret 'HOTP -> ModeState 'HOTP -> (T.Text, ModeState 'HOTP)
hotp Sec{..} (HOTPState i) =
    (formatKey 3 . T.pack $ printf fmt p, HOTPState (i + 1))
  where
    fmt = "%0" ++ show secDigits ++ "d"
    p = hashAlgo secAlgo >>~ \(I a) -> OTP.hotp a secKey i secDigits

-- | (Purely) generate a TOTP (time-based) code, for a given time.
totp_ :: Secret 'TOTP -> UTCTime -> T.Text
totp_ Sec{..} t = hashAlgo secAlgo >>~ \(I a) -> formatKey 3 . T.pack $
    printf fmt $ OTP.totp a secKey (90 `addUTCTime` t) 30 secDigits
  where
    fmt = "%0" ++ show secDigits ++ "d"

-- | Generate a TOTP (time-based) code in IO for the current time.
totp :: Secret 'TOTP -> IO T.Text
totp s = totp_ s <$> getCurrentTime

-- | Abstract over both 'hotp' and 'totp'.
otp :: forall m. SingI m => Secret m -> ModeState m -> IO (T.Text, ModeState m)
otp = case sing @_ @m of
    SHOTP -> curry $ return . uncurry hotp
    STOTP -> curry $ bitraverse totp return

-- | Some sort of RankN lens and traversal over a 'SomeSecret'.  Allows you
-- to traverse (effectfully map) over the 'ModeState' in
-- a 'SomeSecretState', with access to the 'Secret' as well.
--
-- With this you can implement getters and setters.  It's also used by the
-- library to update the 'ModeState' in IO.
someSecret
    :: Functor f
    => (forall m. SingI m => Secret m -> ModeState m -> f (ModeState m))
    -> SomeSecretState
    -> f SomeSecretState
someSecret f = \case
    s :=> (sc :&: ms) -> withSingI s $ ((s :=>) . (sc :&:)) <$> f sc ms

deriving instance (Functor f, Functor g) => Functor (f :.: g)

-- | A RankN traversal over all of the 'Secret's and 'ModeState's in
-- a 'Vault'.
vaultSecrets
    :: Applicative f
    => (forall m. SingI m => Secret m -> ModeState m -> f (ModeState m))
    -> Vault
    -> f Vault
vaultSecrets f = (_Vault . traverse) (someSecret f)

-- | A lens into the list of 'SomeSecretState's in a 'Vault'.  Should be an
-- Iso but we don't want a lens dependency now, do we.
_Vault
    :: Functor f
    => ([SomeSecretState] -> f [SomeSecretState])
    -> Vault
    -> f Vault
_Vault f s = Vault <$> f (vaultList s)

-- | A parser for a otpauth URI.
secretURI :: P.Parser SomeSecretState
secretURI = do
    _ <- P.string "otpauth://"
    m <- otpMode
    _ <- P.char '/'
    (a,i) <- otpLabel
    ps <- M.fromList <$> param `P.sepBy` P.char '&'
    sec <- case M.lookup "secret" ps of
      Nothing -> fail "Required parameter 'secret' not present"
      Just s ->
        case decodePad s of
          Just s' -> return s'
          Nothing -> fail $ "Not a valid base-32 string: " ++ T.unpack s
    let dig = fromMaybe 6 $ do
          d <- M.lookup "digits" ps
          readMaybe @Word $ T.unpack d
        i' = i <|> M.lookup "issuer" ps
        alg = fromMaybe HASHA1 $ do
          al <- M.lookup "algorithm" ps
          parseAlgo . T.unpack . T.map toLower $ al
        secr :: forall m. Secret m
        secr = Sec a i' alg dig sec

    withSomeSing m $ \case
      SHOTP -> case M.lookup "counter" ps of
          Nothing -> fail "Paramater 'counter' required for hotp mode"
          Just (T.unpack->c) -> case readMaybe c of
            Nothing -> fail $ "Could not parse 'counter' parameter: " ++ c
            Just c' -> return $ SHOTP :=> secr :&: HOTPState c'
      STOTP -> return $ STOTP :=> secr :&: TOTPState
  where
    otpMode :: P.Parser Mode
    otpMode = HOTP <$ P.string "hotp"
          <|> HOTP <$ P.string "HOTP"
          <|> TOTP <$ P.string "totp"
          <|> TOTP <$ P.string "TOTP"
    otpLabel :: P.Parser (T.Text, Maybe T.Text)
    otpLabel = do
      x <- P.some (P.try (mfilter (/= ':') uriChar))
      rest <- Just <$> (colon
                     *> P.many (P.try uriSpace)
                     *> P.some (P.try uriChar)
                     <* P.char '?'
                       )
          <|> Nothing <$ P.char '?'
      return $ case rest of
        Nothing -> (T.pack . U.decode $ x, Nothing)
        Just y  -> (T.pack . U.decode $ y, Just . T.pack . U.decode $ x)
    param :: P.Parser (T.Text, T.Text)
    param = do
      k <- T.map toLower . T.pack <$> P.some (P.try uriChar)
      _ <- P.char '='
      v <- T.pack <$> P.some (P.try uriChar)
      return (k, v)
    uriChar = P.satisfy U.isAllowed
          <|> P.char '@'
          <|> (do x <- U.decode <$> sequence [P.char '%', P.hexDigit, P.hexDigit]
                  case x of
                    [y] -> return y
                    _   -> fail "Invalid URI escape code"
              )
    colon    = void (P.char ':') <|> void (P.string "%3A")
    uriSpace = void P.space      <|> void (P.string "%20")

-- | Parse a valid otpauth URI and initialize its state.
--
-- See <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
parseSecretURI
    :: String
    -> Either String SomeSecretState
parseSecretURI s = case P.parseString secretURI mempty s of
    P.Success r -> Right r
    P.Failure e -> Left (show e)
