{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- AES-GCM 256
module Dhall.Secret.Aes where
import           Crypto.Cipher.AES       (AES256)
import           Crypto.Cipher.Types     (AuthTag, BlockCipher (..),
                                          Cipher (..), IV,
                                          KeySizeSpecifier (..), cipherInit,
                                          makeIV)
import           Crypto.Error            (CryptoError (..), CryptoFailable (..),
                                          throwCryptoErrorIO)

import qualified Crypto.Random.Types     as CRT

import           Control.Monad.IO.Class  (MonadIO (liftIO))
import           Crypto.Cipher.AESGCMSIV (Nonce, nonce)
import qualified Crypto.Cipher.AESGCMSIV as AESGCM
import           Crypto.Hash             (SHA256 (SHA256), hashWith)
import qualified Crypto.KDF.Argon2       as A2
import           Crypto.Random           (MonadRandom (getRandomBytes))
import           Data.ByteArray          (ByteArray, ByteArrayAccess, Bytes,
                                          convert)
import           Data.ByteArray.Encoding (Base (Base64), convertFromBase)
import           Data.Text               (Text)
import qualified Data.Text.Encoding      as T

hashOpts = A2.Options 16 4096 2 A2.Argon2i A2.Version13

encrypt :: (ByteArray a, ByteArrayAccess password, ByteArrayAccess aad) => password -> aad -> a -> IO (AuthTag, a, Nonce, a)
encrypt password context msg = do
  salt :: a <- getRandomBytes 8
  nonce <- AESGCM.generateNonce
  throwCryptoErrorIO $ do
    key :: a <- A2.hash hashOpts password salt 32
    aes :: AES256 <- cipherInit key
    let (tag, cipher) = AESGCM.encrypt aes nonce context msg
    return (tag, salt, nonce, cipher)

decrypt :: (ByteArray a, ByteArrayAccess password, ByteArrayAccess baa) => password -> baa -> a -> AuthTag -> a -> baa -> IO a
decrypt password context cipher tag salt iv = throwCryptoErrorIO $ do
  key :: a <- A2.hash hashOpts password salt 32
  n <- nonce iv
  aes :: AES256 <- cipherInit key
  let abc :: Maybe a = AESGCM.decrypt aes n context cipher tag
  case abc of
    Just a  -> pure a
    Nothing -> error "AES Decrypt Failed"

