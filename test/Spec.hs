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
testSymm = "encrypt decrypt with Symmetric Algo" ~: snapshot "./test/example02.dhall" "./test/example02.encrypted.dhall"

main :: IO ()
main = do
  alg <- getEnv "TEST_ALG"
  setEnv "MY_AES_SECRET" "super-secure-secret"
  TIO.writeFile "./Type.dhall" (pretty Lib.secretType)
  case alg of
    Just "KMS" ->  runTestTTAndExit (test testKms)
    Just "ALL" -> runTestTTAndExit (test [testKms, testSymm])
    _          -> runTestTTAndExit (test [testGenIdentity])

snapshot src expect = do
  expr <- TIO.readFile src >>= inputExpr
  encrypted1 <- Lib.encrypt expr >>= inputExpr . (pretty . Lib.defineVar)
  encrypted2 <- TIO.readFile "./test/example02.encrypted.dhall" >>= inputExpr
  decrypted1 <- pretty . Lib.defineVar <$> Lib.decrypt (Lib.DecryptPreference False) encrypted1
  decrypted2 <- pretty . Lib.defineVar <$> Lib.decrypt (Lib.DecryptPreference False) encrypted2
  assertEqual "snapshot" decrypted1 decrypted2
