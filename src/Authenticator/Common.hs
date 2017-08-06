{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}

-- |
-- Module      : Authenticator.Common
-- Description : Utilty functions
-- Copyright   : (c) Justin Le 2017
-- License     : MIT
-- Maintainer  : justin@jle.im
-- Stability   : unstable
-- Portability : portable
--
-- Common utility functions and values used throughout the library.
--


module Authenticator.Common (
    hlSettings
  , decodePad
  ) where

import           Control.Monad.IO.Class
import           Data.Char
import           Data.Semigroup
import qualified Codec.Binary.Base32      as B32
import qualified Data.ByteString          as BS
import qualified Data.Text                as T
import qualified Data.Text.Encoding       as T
import qualified System.Console.Haskeline as L

-- | Default settings for haskeline.
hlSettings :: forall m. MonadIO m => L.Settings m
hlSettings = (L.defaultSettings @m) { L.complete       = L.noCompletion 
                                    , L.autoAddHistory = False
                                    }

-- | Pad and decode a base32-encoded value from its 'Text' prepresentation.
decodePad :: T.Text -> Maybe BS.ByteString
decodePad = either (const Nothing) Just
          . B32.decode
          . (\s' -> s' <> BS.replicate ((8 - BS.length s') `mod` 8) p)
          . T.encodeUtf8
          . T.map toUpper
          . T.filter isAlphaNum
  where
    p = fromIntegral $ ord '='
