{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TupleSections #-}

module Encrypted (
    Enc(..)
  , withEnc
  , overEnc
  , getEnc
  , mkEnc
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
withEnc c k f e = do
    x <- getEnc c e
    (o, y) <- f x
    e' <- mkEnc c k y
    return (o, e')

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
    -> Enc a
    -> IO a
getEnc c (Enc e) = do
    Right x <- fmap (B.decode . BSL.fromStrict) <$> G.decryptVerify c e
    return x

mkEnc
    :: B.Binary a
    => G.Ctx
    -> G.Key
    -> a
    -> IO (Enc a)
mkEnc c k x = do
    Right e' <- G.encryptSign c [k] G.NoFlag . BSL.toStrict . B.encode $ x
    return (Enc e')
