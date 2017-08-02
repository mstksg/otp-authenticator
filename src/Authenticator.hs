{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving  #-}
{-# LANGUAGE TemplateHaskell     #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeFamilies        #-}
{-# LANGUAGE TypeInType          #-}
{-# LANGUAGE TypeOperators       #-}

module Authenticator (
  ) where

import           Data.Dependent.Sum
import           Data.Functor.Identity
import           Data.Kind
import           Data.OTP
import           Data.Singletons
import           Data.Singletons.TH
import           Data.Text
import           Data.Type.Conjunction
import           Data.Type.Equality
import           GHC.Generics           (Generic)
import           Type.Class.Higher
import           Type.Class.Witness
import           Type.Reflection
import qualified Crypto.Gpgme           as GPG
import qualified Data.Binary            as B
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base32 as B32
import qualified Data.Text              as T

$(singletons [d|
  data Mode = HOTP | TOTP
    deriving Generic
  |])

instance B.Binary Mode

data family ModeState :: Mode -> Type
data instance ModeState 'HOTP = HOTPState Integer
  deriving Generic
data instance ModeState 'TOTP = TOTPState
  deriving Generic

instance B.Binary (ModeState HOTP)
instance B.Binary (ModeState TOTP)

modeStateBinary :: Sing m -> Wit1 B.Binary (ModeState m)
modeStateBinary = \case
    SHOTP -> Wit1
    STOTP -> Wit1

data Secret :: Mode -> Type where
    Sec :: { secAccount :: T.Text
           , secIssuer  :: Maybe T.Text
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
  deriving Generic

instance B.Binary Store


