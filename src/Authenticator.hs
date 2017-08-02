{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE LambdaCase          #-}
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
  ) where

import           Crypto.Hash.Algorithms
import           Data.Dependent.Sum
import           Data.Functor.Identity
import           Data.Kind
import           Data.Singletons
import           Data.Singletons.TH
import           Data.Text
import           Data.Time.Clock
import           Data.Type.Combinator
import           Data.Type.Conjunction
import           Data.Type.Equality
import           Data.Word
import           GHC.Generics           (Generic)
import           Type.Class.Higher
import           Type.Class.Witness
import           Type.Reflection
import qualified Crypto.Gpgme           as GPG
import qualified Data.Binary            as B
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base32 as B32
import qualified Data.OTP               as OTP
import qualified Data.Text              as T

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

instance B.Binary (ModeState HOTP)
instance B.Binary (ModeState TOTP)

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
-- data Store = Store { storeHOTP :: [(Secret 'HOTP, Integer)]
--                    , storeTOTP :: [Secret 'TOTP]
--                    }
  deriving Generic

instance B.Binary Store

hotp :: Secret 'HOTP -> ModeState 'HOTP -> (Word32, ModeState 'HOTP)
hotp Sec{..} (HOTPState i) = (p, HOTPState (i + 1))
  where
    p = hashAlgo secAlgo >>~ \(I a) -> OTP.hotp a secKey i secDigits

totp :: Secret 'TOTP -> UTCTime -> Word32
totp Sec{..} t = hashAlgo secAlgo >>~ \(I a) ->
    OTP.totp a secKey t 30 secDigits

otp :: forall m. SingI m => Secret m -> ModeState m -> IO (Word32, ModeState m)
otp = case sing @_ @m of
    SHOTP -> \s ms -> return $ hotp s ms
    STOTP -> \s ms -> ((, ms) . totp s) <$> getCurrentTime
