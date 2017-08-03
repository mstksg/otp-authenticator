{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TupleSections #-}

module Encrypted (
    Enc(..)
  , withEnc
  , overEnc
  , getEnc
  ) where

import           Data.Either
import           Control.Monad
import           GHC.Generics         (Generic)
import qualified Crypto.Gpgme         as G
import qualified Data.Binary          as B
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BSL

data Enc a = Enc { encBytes :: G.Encrypted }
    deriving Generic

instance B.Binary (Enc a)

withEnc
    :: B.Binary a
    => G.Ctx
    -> G.Key
    -> (a -> IO (b, a))
    -> Enc a
    -> IO (b, Enc a)
withEnc c k f (Enc e) = do
    Right x <- fmap (B.decode . BSL.fromStrict) <$> G.decryptVerify c e
    (o, y) <- f x
    Right e' <- G.encryptSign c [k] G.NoFlag . BSL.toStrict . B.encode $ y
    return (o, Enc e')

overEnc
    :: B.Binary a
    => G.Ctx
    -> G.Key
    -> (a -> IO a)
    -> Enc a
    -> IO (Enc a)
overEnc c k f = fmap snd . withEnc c k (fmap ((),) . f)

getEnc
    :: B.Binary a
    => G.Ctx
    -> G.Key
    -> Enc a
    -> IO a
getEnc c k = fmap fst . withEnc c k (pure . join (,))

  
