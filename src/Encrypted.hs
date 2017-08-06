{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StrictData    #-}
{-# LANGUAGE TupleSections #-}

-- |
-- Module      : Encrypted
-- Description : Abstracting over an encrypted value with gpgme and gnupg
-- Copyright   : (c) Justin Le 2017
-- License     : MIT
-- Maintainer  : justin@jle.im
-- Stability   : unstable
-- Portability : portable
--
-- Basically provides @'Enc' a@, which abstracts over an encrypted @a@.
-- Can only be read by invoking GnuPG in 'IO', where the user needs to
-- provide their key to decrypt.
--
-- One main advantage is that an @'Enc' a@ can be seriealized and
-- deserialized using its 'Binary' instance, providing type-safe
-- deserialization into encrypted values.
--
-- Might be pulled out to an external package some day.
--

module Encrypted (
    Enc(..)
  , mkEnc
  , overEnc
  , getEnc
  , withEnc
  ) where

import           GHC.Generics         (Generic)
import qualified Crypto.Gpgme         as G
import qualified Data.Binary          as B
import qualified Data.ByteString.Lazy as BSL

-- | An @'Enc' a@ abstracts over a encrypted @a@.
--
-- Has a useful 'Binary' instance, which allows type-safe deserialization
-- into encrypted values.
data Enc a = Enc { encBytes :: G.Encrypted }
    deriving Generic

instance B.Binary (Enc a)

-- | A variation of 'overEnc' that allows the user to also return a value
-- produced from the decrypted value.  Re-encrypts the changed value using
-- the given GnuPG key.
withEnc
    :: B.Binary a
    => G.Ctx
    -> G.Key
    -> Enc a
    -> (a -> IO (b, a))
    -> IO (b, Enc a)
withEnc c k e f = do
    x <- getEnc c e
    (o, y) <- f x
    e' <- mkEnc c k y
    return (o, e')

-- | Modify an encrypted value with a given @a -> IO a@ function,
-- re-encrypting it with the given GnuPG key.  The decrypted value never
-- leaves the closure.
overEnc
    :: B.Binary a
    => G.Ctx
    -> G.Key
    -> Enc a
    -> (a -> IO a)
    -> IO (Enc a)
overEnc c k e f = fmap snd . withEnc c k e $ (fmap ((),) . f)

-- | Extract a value from an 'Enc', using a compatible key in the GnuPG
-- environment.
getEnc
    :: B.Binary a
    => G.Ctx
    -> Enc a
    -> IO a
getEnc c (Enc e) = do
    Right x <- fmap (B.decode . BSL.fromStrict) <$> G.decrypt c e
    return x

-- | Wrap a value into an 'Enc', using a given GnuPG key.
mkEnc
    :: B.Binary a
    => G.Ctx
    -> G.Key
    -> a
    -> IO (Enc a)
mkEnc c k x = do
    Right e' <- G.encrypt c [k] G.NoFlag . BSL.toStrict . B.encode $ x
    return (Enc e')
