module Main where
import           Data.Text
import qualified Data.Text.IO             as TIO
import           Dhall
import           Dhall.Core               (pretty)
import qualified Lib
import           System.Environment       (setEnv)
import           System.Environment.Blank (getEnv)
import           Test.HUnit

testKms = "encrypt decrypt with KMS" ~: snapshot "./test/example01.dhall" "./test/example01.expected.dhall"
testAes = "encrypt decrypt with AES" ~: snapshot "./test/example02.dhall" "./test/example02.expected.dhall"

main :: IO ()
main = do
  alg <- getEnv "TEST_ALG"
  setEnv "MY_AES_SECRET" "super-secret"
  TIO.writeFile "./Type.dhall" (pretty Lib.secretType)
  case alg of
    Just "KMS" ->  runTestTTAndExit (test testKms)
    Just "ALL" -> runTestTTAndExit (test [testKms, testAes])
    _          -> runTestTTAndExit (test [testAes])


snapshot src expect = do
  text <- TIO.readFile src
  expr <- inputExpr text
  expected <- TIO.readFile expect
  encrypted <- Lib.encrypt expr
  decrypted <- Lib.decrypt (Lib.DecryptPreference False) encrypted
  assertEqual "snapshot" expected (pretty decrypted <> pack "\n")
