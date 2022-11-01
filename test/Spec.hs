module Main where
import           Age
import           Data.Text
import qualified Data.Text.IO             as TIO
import           Dhall
import           Dhall.Core               (pretty)
import qualified Dhall.Secret             as Lib
import           System.Environment       (setEnv)
import           System.Environment.Blank (getEnv)
import           Test.HUnit
testKms = "encrypt decrypt with KMS" ~: snapshot "./test/example01.dhall" "./test/example01.encrypted.dhall"
testAge = "encrypt decrypt with Age Algo" ~: snapshot "./test/example02.dhall" "./test/example02.encrypted.dhall"

main :: IO ()
main = do
  alg <- getEnv "TEST_ALG"
  setEnv "DHALL_SECRET_AGE_KEYS" "AGE-SECRET-KEY-1SR4ZPP77HDEUJJ9MXJPFQFKHNJ57XKUHXW7TFZ6R3AV59M3KHP2S45ZFW9\nAGE-SECRET-KEY-1HKC2ZRPFFY66049G5EWYLT2PMYKTPN6UW6RFEEEN3JEEWTFFFDNQ2QTC8M\nAGE-SECRET-KEY-1GLAZ75TDSSR647WXD0MH3RUU8XGRK6R5SD8UGQ6C6R9MCYR03ULQSUC7D6"
  TIO.writeFile "./src/Type.dhall" (pretty Lib.secretType)
  case alg of
    Just "KMS" ->  runTestTTAndExit (test testKms)
    Just "ALL" -> runTestTTAndExit (test [testKms, testAgeEncryption, testAge])
    _          -> runTestTTAndExit (test [testAgeEncryption, testAge])

snapshot src expect = do
  expr <- TIO.readFile src >>= inputExpr
  encrypted1 <- Lib.encrypt expr >>= inputExpr . (pretty . Lib.defineVar)
  encrypted2 <- TIO.readFile expect >>= inputExpr
  decrypted1 <- pretty . Lib.defineVar <$> Lib.decrypt (Lib.DecryptPreference False) encrypted1
  decrypted2 <- pretty . Lib.defineVar <$> Lib.decrypt (Lib.DecryptPreference False) encrypted2
  assertEqual "snapshot" decrypted1 decrypted2
