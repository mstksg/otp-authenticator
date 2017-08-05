
module Authenticator.Common (
    query
  ) where

import           System.IO

query :: String -> IO String
query p = do
    putStr $ p ++ ": "
    hFlush stdout
    getLine
