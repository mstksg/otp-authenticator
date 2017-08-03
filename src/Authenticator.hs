{-# LANGUAGE DeriveFunctor       #-}
{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving  #-}
{-# LANGUAGE TemplateHaskell     #-}
{-# LANGUAGE TupleSections       #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeFamilies        #-}
{-# LANGUAGE TypeInType          #-}
{-# LANGUAGE TypeOperators       #-}

module Authenticator (
    Mode(..)
  , Sing(SHOTP, STOTP)
  , HashAlgo(..)
  , parseAlgo
  , Secret(..)
  , Store(..)
  , _Store
  , hotp
  , totp
  , totp_
  , otp
  , someotp
  , someSecret
  , storeSecrets
  , initState
  , describeSecret
  ) where

import           Crypto.Hash.Algorithms
import           Data.Bitraversable
import           Data.Char
import           Data.Dependent.Sum
import           Data.Kind
import           Data.Semigroup
import           Data.Singletons
import           Data.Singletons.TH
import           Data.Time.Clock
import           Data.Type.Combinator
import           Data.Type.Conjunction
import           Data.Word
import           GHC.Generics              (Generic)
import           Type.Class.Higher
import           Type.Class.Witness
import qualified Crypto.Gpgme              as GPG
import qualified Data.Binary               as B
import qualified Data.ByteString           as BS
import qualified Data.OTP                  as OTP
import qualified Data.Text                 as T

$(singletons [d|
  data Mode = HOTP | TOTP
    deriving Generic
  |])

instance B.Binary Mode

data family ModeState :: Mode -> Type
data instance ModeState 'HOTP = HOTPState Word64
  deriving Generic
data instance ModeState 'TOTP = TOTPState
  deriving Generic

instance B.Binary (ModeState 'HOTP)
instance B.Binary (ModeState 'TOTP)

modeStateBinary :: Sing m -> Wit1 B.Binary (ModeState m)
modeStateBinary = \case
    SHOTP -> Wit1
    STOTP -> Wit1

data HashAlgo = HASHA1 | HASHA256 | HASHA512
  deriving Generic

instance B.Binary HashAlgo

hashAlgo :: HashAlgo -> SomeC HashAlgorithm I
hashAlgo HASHA1   = SomeC (I SHA1  )
hashAlgo HASHA256 = SomeC (I SHA256)
hashAlgo HASHA512 = SomeC (I SHA512)

parseAlgo :: String -> Maybe HashAlgo
parseAlgo = (`lookup` algos) . map toLower . unwords . words
  where
    algos = [("sha1", HASHA1)
            ,("sha256", HASHA256)
            ,("sha512", HASHA512)
            ]

data Secret :: Mode -> Type where
    Sec :: { secAccount :: T.Text
           , secIssuer  :: Maybe T.Text
           , secAlgo    :: HashAlgo
           , secDigits  :: Word
           , secKey     :: BS.ByteString
           }
        -> Secret m
  deriving Generic

instance B.Binary (Secret m)

describeSecret :: Secret m -> T.Text
describeSecret s = secAccount s <> case secIssuer s of
                                     Nothing -> ""
                                     Just i  -> " / " <> i

instance B.Binary (DSum Sing (Secret :&: ModeState)) where
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

data Store = Store { storeList :: [DSum Sing (Secret :&: ModeState)] }
  deriving Generic

instance B.Binary Store

initState :: forall m. SingI m => ModeState m
initState = case sing @_ @m of
    SHOTP -> HOTPState 0
    STOTP -> TOTPState

hotp :: Secret 'HOTP -> ModeState 'HOTP -> (Word32, ModeState 'HOTP)
hotp Sec{..} (HOTPState i) = (p, HOTPState (i + 1))
  where
    p = hashAlgo secAlgo >>~ \(I a) -> OTP.hotp a secKey i secDigits

totp_ :: Secret 'TOTP -> UTCTime -> Word32
totp_ Sec{..} t = hashAlgo secAlgo >>~ \(I a) ->
    OTP.totp a secKey (30 `addUTCTime` t) 30 secDigits

totp :: Secret 'TOTP -> IO Word32
totp s = totp_ s <$> getCurrentTime

otp :: forall m. SingI m => Secret m -> ModeState m -> IO (Word32, ModeState m)
otp = case sing @_ @m of
    SHOTP -> curry $ return . uncurry hotp
    STOTP -> curry $ bitraverse totp return

someotp :: DSum Sing (Secret :&: ModeState) -> IO (Word32, DSum Sing (Secret :&: ModeState))
someotp = getComp . someSecret (\s -> Comp . otp s)

someSecret
    :: Functor f
    => (forall m. SingI m => Secret m -> ModeState m -> f (ModeState m))
    -> DSum Sing (Secret :&: ModeState)
    -> f (DSum Sing (Secret :&: ModeState))
someSecret f = \case
    s :=> (sc :&: ms) -> withSingI s $ ((s :=>) . (sc :&:)) <$> f sc ms

deriving instance (Functor f, Functor g) => Functor (f :.: g)

storeSecrets
    :: Applicative f
    => (forall m. SingI m => Secret m -> ModeState m -> f (ModeState m))
    -> Store
    -> f Store
storeSecrets f = (_Store . traverse) (someSecret f)

_Store
    :: Functor f
    => ([DSum Sing (Secret :&: ModeState)] -> f [DSum Sing (Secret :&: ModeState)])
    -> Store
    -> f Store
_Store f s = Store <$> f (storeList s)

