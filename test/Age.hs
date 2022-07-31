module Age where
import           Data.ByteString  (empty)
import           Dhall.Secret.Age
import           Test.HUnit

testGenIdentity = TestCase $ do
      i <- generateX25519Identity
      s <- mkStanza (toRecipient i) empty
      print $ s
