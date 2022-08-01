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
testGenIdentity = TestCase $ do
  i <- generateX25519Identity
  TIO.writeFile "./test.key" (T.pack $ show i)
  let r = toRecipient i
  plaintext <- TIO.readFile "./test.org"
  encrypted <- encrypt [r] (TE.encodeUtf8 plaintext)
  TIO.writeFile "./test.age" (TE.decodeUtf8 encrypted)
