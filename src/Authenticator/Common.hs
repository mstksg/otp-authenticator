{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}

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

hlSettings :: forall m. MonadIO m => L.Settings m
hlSettings = (L.defaultSettings @m) { L.complete       = L.noCompletion 
                                    , L.autoAddHistory = False
                                    }

decodePad :: T.Text -> Maybe BS.ByteString
decodePad = either (const Nothing) Just
          . B32.decode
          . (\s' -> s' <> BS.replicate ((8 - BS.length s') `mod` 8) p)
          . T.encodeUtf8
          . T.map toUpper
          . T.filter isAlphaNum
  where
    p = fromIntegral $ ord '='
