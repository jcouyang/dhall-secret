module Main where
import           Age
import qualified Data.Text.IO             as TIO
import qualified Dhall.Secret             as Lib
import           Dhall.Secret.IO
import           System.Environment       (setEnv)
import           System.Environment.Blank (getEnv)
import           Test.HUnit

testKms = "encrypt decrypt with KMS" ~: snapshot "./test/example01.dhall" "./test/example01.encrypted.dhall"
testAge = "encrypt decrypt with Age Algo" ~: snapshot "./test/example02.dhall" "./test/example02.encrypted.dhall"

main :: IO ()
main = do
  alg <- getEnv "TEST_ALG"
  setEnv "DHALL_SECRET_AGE_KEYS" "AGE-SECRET-KEY-1SR4ZPP77HDEUJJ9MXJPFQFKHNJ57XKUHXW7TFZ6R3AV59M3KHP2S45ZFW9\nAGE-SECRET-KEY-1HKC2ZRPFFY66049G5EWYLT2PMYKTPN6UW6RFEEEN3JEEWTFFFDNQ2QTC8M\nAGE-SECRET-KEY-1GLAZ75TDSSR647WXD0MH3RUU8XGRK6R5SD8UGQ6C6R9MCYR03ULQSUC7D6"
  case alg of
    Just "KMS" ->  runTestTTAndExit (test testKms)
    Just "ALL" -> runTestTTAndExit (test [testKms, testAgeEncryption, testAge])
    _          -> runTestTTAndExit (test [testAgeEncryption, testAge])

snapshot src expect = do
  expr <- TIO.readFile src
  encrypted1 <- parseExpr expr >>= Lib.encrypt >>= prettyExpr
  encrypted2 <- TIO.readFile expect >>= parseExpr
  decrypted1 <- parseExpr encrypted1 >>= Lib.decrypt (Lib.DecryptPreference False) >>= prettyExpr
  decrypted2 <- Lib.decrypt (Lib.DecryptPreference False) encrypted2 >>= prettyExpr
  assertEqual "snapshot" decrypted1 decrypted2
