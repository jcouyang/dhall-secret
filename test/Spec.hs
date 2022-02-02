module Main where
import           Data.Text
import qualified Data.Text.IO as TIO
import           Dhall
import           Dhall.Core   (pretty)
import qualified Lib
import           Test.HUnit

tests = test
  ["encrypt with kms" ~: do
      text <- TIO.readFile "./test/example01.dhall"
      expr <- inputExpr text
      encrypted <- Lib.encrypt expr
      decrypted <- Lib.decrypt encrypted
      assertEqual "asdf" "for (foo 3)," ((unpack . pretty) decrypted)
  ]

main :: IO ()
main = runTestTTAndExit tests
