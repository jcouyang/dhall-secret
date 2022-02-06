{-# LANGUAGE GADTs               #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Aes where
import           Crypto.Cipher.AES       (AES256)
import           Crypto.Cipher.Types     (BlockCipher (..), Cipher (..), IV,
                                          KeySizeSpecifier (..), makeIV)
import           Crypto.Error            (CryptoError (..), CryptoFailable (..))

import qualified Crypto.Random.Types     as CRT

import           Crypto.Hash             (SHA256 (SHA256), hashWith)
import           Data.ByteArray          (ByteArray, ByteArrayAccess, convert)
import           Data.ByteArray.Encoding (Base (Base64), convertFromBase)
import           Data.ByteString         (ByteString)
import           Data.Text               (Text)
import qualified Data.Text.Encoding      as T

data Key c a where
  Key :: (BlockCipher c, ByteArrayAccess a) => a -> Key c a

mkSecretKey  :: forall c a. (BlockCipher c) => c -> ByteString  -> Key c ByteString
mkSecretKey _ a = Key (convert $ hashWith SHA256 a)

-- | Generate a random initialization vector for a given block cipher

genRandomIV :: forall m c. (CRT.MonadRandom m, BlockCipher c) => c -> m (IV c)
genRandomIV _ = do
  bytes :: ByteString <- CRT.getRandomBytes $ blockSize (undefined :: c)
  return $ case makeIV bytes of
    Just iv -> iv
    _       -> error "gen iv failed"

mkIV :: (Monad m, BlockCipher c) => c -> Text -> m (IV c)
mkIV _ bs64 = do
  case convertFromBase Base64 (T.encodeUtf8 bs64) of
    Right (bs :: ByteString) -> case makeIV bs of
      Just iv -> pure iv
      _       -> error "gen iv failed"
    _ -> error "gen iv failed"

initCipher :: (BlockCipher c, ByteArray a) => Key c a -> Either CryptoError c
initCipher (Key k) = case cipherInit k of
  CryptoFailed e -> Left e
  CryptoPassed a -> Right a

encrypt :: (BlockCipher c, ByteArray a) => Key c a -> IV c -> a -> IO a
encrypt secretKey initIV msg =
  case initCipher secretKey of
    Left e  -> error (show e)
    Right c -> pure $ ctrCombine c initIV msg

decrypt :: (BlockCipher c, ByteArray a) => Key c a -> IV c -> a -> IO a
decrypt = encrypt
