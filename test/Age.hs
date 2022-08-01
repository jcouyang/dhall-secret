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
  body <- throwCryptoErrorIO $ do
    nonce <- CC.nonce12 (BS.pack $ take 12 $ repeat 0)
    st0 <- CC.initialize (BS.pack $ take 32 $ repeat 0) nonce
    let (e, st1) = CC.encrypt (BS.pack $ take 16 $ repeat 0) st0
    return $ e <> (convert $ CC.finalize st1)
  print $ b64enc body
  i <- generateX25519Identity
  TIO.writeFile "./test.key" (T.pack $ show i)
  let r = toRecipient i
  encrypted <- encrypt [r] ( "hello world" :: ByteString )
  TIO.writeFile "./test.age" (TE.decodeUtf8 encrypted)
  print encrypted
