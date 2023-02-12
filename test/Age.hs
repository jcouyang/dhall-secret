{-# LANGUAGE OverloadedStrings #-}
module Age where
import qualified Data.ByteString  as BS
import           Dhall.Secret.Age
import           Test.HUnit

testAgeEncryption = TestCase $ do
  i <- generateX25519Identity
  i2 <- generateX25519Identity
  let r = toRecipient i
  let r2 = toRecipient i2
  plaintext <- BS.readFile "./test/age.md"
  encrypted <- encrypt [r, r2] plaintext
  decrypted <- decrypt encrypted [i]
  assertEqual "age encryption" plaintext decrypted
