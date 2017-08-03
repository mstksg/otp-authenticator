{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- import qualified Data.ByteString.Base32 as B32
import           Encrypted
import           System.Environment
import qualified Crypto.Gpgme              as G
import qualified Data.Base32String.Default as B32
import qualified Data.Binary               as B
import qualified Data.ByteString           as BS
import qualified Data.Text.Encoding        as T
import qualified Data.Text.IO              as T

main :: IO ()
main = getArgs >>= \[fing] ->
       G.withCtx "~/.gnupg" "C" G.OpenPGP $ \ctx -> do
    Just k <- G.getKey ctx "67D57F1C" G.NoSecret
    e <- mkEnc ctx k ("Hello, workd!" :: String)
    B.encodeFile "enctest.dat" e
    e' <- B.decodeFile @(Enc String) "enctest.dat"
    putStrLn =<< getEnc ctx e'
