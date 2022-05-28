{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- ChaChaPoly1305
module Dhall.Secret.Chacha where
import           Crypto.Cipher.ChaChaPoly1305 as C
import           Crypto.Error                 (CryptoError (..),
                                               CryptoFailable (..),
                                               throwCryptoErrorIO)
import qualified Crypto.KDF.Argon2            as A2
import           Crypto.MAC.Poly1305          (Auth)
import           Crypto.Random                (MonadRandom (getRandomBytes))
import           Data.ByteArray               (ByteArray, ByteArrayAccess,
                                               Bytes, convert)

hashOpts = A2.Options 16 4096 2 A2.Argon2i A2.Version13

encrypt :: (ByteArray a, ByteArrayAccess baa, ByteArrayAccess aad) => baa -> aad -> a -> IO (Auth, a, Nonce, a)
encrypt password context msg = do
  salt :: a <- getRandomBytes 8
  iv :: a <- getRandomBytes 12
  throwCryptoErrorIO $ do
    key :: a <- A2.hash hashOpts password salt 32
    nonce <- nonce12 iv
    state <- C.finalizeAAD . C.appendAAD context <$> C.initialize key nonce
    let (out:: a, statef) = C.encrypt msg state
    return (finalize statef, salt, nonce, out)

decrypt :: (ByteArray a, ByteArrayAccess password, ByteArrayAccess baa) => password -> baa -> a -> Auth -> a -> baa -> IO a
decrypt password context cipher tag salt iv = throwCryptoErrorIO $ do
  key :: a <- A2.hash hashOpts password salt 32
  nonce <- nonce12 iv
  state <- C.finalizeAAD . C.appendAAD context <$> C.initialize key nonce
  let (out:: a, statef) = C.decrypt cipher state
  return out
