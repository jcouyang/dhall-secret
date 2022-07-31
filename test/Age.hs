{-# LANGUAGE OverloadedStrings #-}
module Age where
import           Data.ByteString  (ByteString, empty)
import           Dhall.Secret.Age
import           Test.HUnit

testGenIdentity = TestCase $ do
      i <- generateX25519Identity
      print i
      let r = toRecipient i
      print r
      encrypted <- encrypt [r] ( "hello world" :: ByteString )
      print encrypted
