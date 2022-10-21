{-# LANGUAGE OverloadedStrings #-}
module Age where
import qualified Crypto.Cipher.ChaChaPoly1305 as CC
import           Crypto.Error                 (throwCryptoErrorIO)
import           Data.ByteArray               (ByteArray, ByteArrayAccess,
                                               Bytes, convert, pack)
import           Data.ByteString              (ByteString, empty)
import qualified Data.ByteString              as BS
import qualified Data.Text                    as T
import qualified Data.Text.Encoding           as TE
import qualified Data.Text.IO                 as TIO
import           Dhall.Secret.Age
import           Test.HUnit

testAgeEncryption = TestCase $ do
  i <- generateX25519Identity
  i2 <- generateX25519Identity
  let r = toRecipient i
  let r2 = toRecipient i2
  plaintext <- BS.readFile "./README.md"
  encrypted <- encrypt [r, r2] plaintext
  print encrypted
  decrypted <- decrypt encrypted [i]
  assertEqual "age encryption" plaintext decrypted
