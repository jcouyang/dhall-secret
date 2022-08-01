{-# LANGUAGE OverloadedStrings #-}
module Age where
import           Data.ByteString    (ByteString, empty)
import qualified Data.Text          as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO       as TIO
import           Dhall.Secret.Age
import           Test.HUnit

testGenIdentity = TestCase $ do
      i <- generateX25519Identity
      TIO.writeFile "./test.key" (T.pack $ show i)
      let r = toRecipient i
      encrypted <- encrypt [r] ( "hello world" :: ByteString )
      TIO.writeFile "./test.age" (TE.decodeUtf8 encrypted)
      print encrypted
