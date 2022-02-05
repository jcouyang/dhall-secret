module Main where
import           Data.Text
import qualified Data.Text.IO as TIO
import           Dhall
import           Dhall.Core   (pretty)
import qualified Lib
import           Test.HUnit

tests = test
  [--"encrypt decrypt with kms" ~: snapshot "./test/example01.dhall" "./test/example01.expected.dhall",
    "encrypt decrypt with AES" ~: snapshot "./test/example02.dhall" "./test/example02.expected.dhall"
  ]

main :: IO ()
main = runTestTTAndExit tests


snapshot src expect = do
  text <- TIO.readFile src
  expr <- inputExpr text
  expected <- TIO.readFile expect
  encrypted <- Lib.encrypt expr
  decrypted <- Lib.decrypt encrypted
  assertEqual "snapshot" expected (pretty decrypted <> pack "\n")
