-- https://github.com/C2SP/C2SP/blob/bb6dd888ef54df1b2df1c12dc3e3d05d129ffc0d/age.md
module Dhall.Secret.Age where
import qualified Codec.Binary.Bech32          as Bech32
import           Control.Arrow                (Arrow (first),
                                               ArrowChoice (left))
import           Control.Exception            (throwIO)
import           Control.Monad                (join)
import           Control.Monad.IO.Class       (MonadIO (liftIO))
import           Crypto.Cipher.ChaChaPoly1305 as CC (decrypt, encrypt, finalize,
                                                     finalizeAAD, initialize,
                                                     nonce12)
import           Crypto.Cipher.Types          (Cipher (cipherInit))
import           Crypto.Error                 (maybeCryptoError,
                                               throwCryptoError,
                                               throwCryptoErrorIO)
import           Crypto.Hash                  (SHA256)
import           Crypto.KDF.HKDF              (PRK)
import qualified Crypto.KDF.HKDF              as HKDF
import           Crypto.MAC.HMAC              (HMAC (HMAC), hmac)
import qualified Crypto.PubKey.Curve25519     as X25519
import qualified Crypto.PubKey.Curve25519     as X255519
import           Crypto.Random                (MonadRandom (getRandomBytes))
import           Data.ByteArray               (ByteArray, ByteArrayAccess,
                                               Bytes, convert, pack)
import           Data.ByteArray.Encoding      (Base (Base64, Base64URLUnpadded),
                                               convertToBase)
import           Data.ByteString              (ByteString, empty, intercalate)
import qualified Data.ByteString              as BS
import           Data.ByteString.Base64       (decodeBase64,
                                               decodeBase64Unpadded,
                                               encodeBase64Unpadded')
import           Data.Char                    (isSpace)
import           Data.Either                  (fromRight)
import           Data.List                    (find)
import           Data.Maybe                   (fromMaybe, isJust)
import           Data.PEM                     (PEM (..), pemParseBS, pemWriteBS)
import           Data.Text                    (Text)
import qualified Data.Text                    as T
import qualified Data.Text.Encoding           as TE
import           Data.Word                    (Word8)
data Stanza = Stanza
  { stzType:: ByteString
  , stzArgs :: [ByteString]
  , stzBody :: ByteString
  }
data X25519Recipient = X25519Recipient X25519.PublicKey
instance Show X25519Recipient where
  show (X25519Recipient pub) = T.unpack $ b32 "age" pub

data X25519Identity = X25519Identity X25519.PublicKey X25519.SecretKey
instance Show X25519Identity where
  show (X25519Identity _ sec) = T.unpack $ T.toUpper $ b32 "AGE-SECRET-KEY-" sec

data Header = Header [Stanza] ByteString

data CipherBlock = Cipher Header ByteString ByteString

encrypt :: [X25519Recipient] -> ByteString -> IO ByteString
encrypt recipients msg = do
  fileKey <- getRandomBytes 16 :: IO ByteString
  nonce <- getRandomBytes 16 :: IO ByteString
  stanzas <- traverse (mkStanza fileKey) recipients
  body <-  encryptChunks (payloadKey nonce fileKey) zeroNonce msg
  pure $ pemWriteBS $ PEM { pemName ="AGE ENCRYPTED FILE", pemHeader = [], pemContent = mkHeader fileKey stanzas <> nonce <> body}
  where
    payloadKey :: ByteString -> ByteString -> ByteString
    payloadKey nonce filekey = HKDF.expand (HKDF.extract  nonce filekey ::PRK SHA256) ("payload" :: ByteString) 32

decrypt :: ByteString -> [X25519Identity] -> IO ByteString
decrypt ciphertext identities = do
  (Cipher header nonce body) <- _ $ parseCipher ciphertext
  case findFileKey identities header of
    Just key -> decryptChunks key nonce body
    Nothing  -> _

decryptChunks :: ByteString -> ByteString -> ByteString -> IO ByteString
decryptChunks key nonce body = case BS.splitAt (64 * 1024) body of
  (head, tail) | tail == BS.empty -> decryptChunk key nonce head (BS.pack [1])
  (head, tail)                    -> decryptChunk key nonce head (BS.pack [0]) <> decryptChunks key (incNonce nonce) tail

decryptChunk :: ByteString -> ByteString -> ByteString -> ByteString -> IO ByteString
decryptChunk key nonce msg isFinal = throwCryptoErrorIO $ do
    payloadNonce <- nonce12 $ (nonce <> isFinal)
    st <- CC.initialize key payloadNonce
    let (d, _) = CC.decrypt msg st
    return $ d

parseCipher :: ByteString -> Either String CipherBlock
parseCipher ct = do
  pems <- pemParseBS ct
  content <- left show $ decodeBase64 $ pemContent (head pems)
  let (v1line, rest) = BS.break (== 0x0a) content
  (header, rest2) <- parseHeader (Header [] "") (BS.drop 1 rest)
  let (nonce, body) = BS.splitAt 12 rest2
  pure $ Cipher header nonce body

parseHeader :: Header ->  ByteString -> Either String (Header, ByteString)
parseHeader (Header stz mac) content = do
  let (recipients, rest1) = BS.break isLF $ content
  case BS.take 3 recipients of
    "---" -> Right $ (Header stz (BS.drop 4 recipients), BS.drop 1 rest1)
    "-> " -> do
      let (fileKey, rest2) = BS.break isLF $ BS.drop 1 rest1
      let (stztype, rest11) = BS.break isSpace recipients
      let (stzarg, rest12) = BS.break isSpace $ BS.drop 1 rest11
      let (stzbody, rest13) = BS.break isLF $ BS.drop 1 rest12
      let st = Stanza {stzType = stztype, stzArgs = [stzarg], stzBody = stzbody}
      parseHeader (Header (st:stz) mac) (BS.drop 1 rest13)
    _ -> Left "invalid header stanza format"
  where
    isLF = (== 0x0a)
    isSpace = (== 0x20)

findFileKey :: [X25519Identity] -> Header -> Maybe ByteString
findFileKey identities (Header stz mac) = join $ find isJust $ hasKey <$> identities <*> stz
  where
    hasKey :: X25519Identity -> Stanza -> Maybe ByteString
    hasKey (X25519Identity pk sec) stz = maybeCryptoError $ do
      let theirPkBs = fromRight "" $ decodeBase64Unpadded $ head (stzArgs stz)
      theirPk <- X25519.publicKey theirPkBs
      let shareKey = X25519.dh theirPk sec
      let salt = (convert theirPk) <> (convert pk)
      let wrappingKey = hkdf "age-encryption.org/v1/X25519" (convert shareKey) salt
      nonce <- CC.nonce12 (BS.pack $ take 12 $ repeat 0)
      st0 <- CC.initialize wrappingKey nonce
      let (e, st1) = CC.decrypt (stzBody stz) st0
      return e


generateX25519Identity :: IO X25519Identity
generateX25519Identity = do
  sec <- X25519.generateSecretKey
  pure $ X25519Identity (X25519.toPublic sec) sec

encryptChunks :: ByteString -> ByteString -> ByteString -> IO ByteString
encryptChunks key nonce msg = case BS.splitAt (64 * 1024) msg of
  (head, tail) | tail == BS.empty -> encryptChunk key nonce head (BS.pack [1])
  (head, tail)                    -> encryptChunk key nonce head (BS.pack [0]) <> encryptChunks key (incNonce nonce) tail

encryptChunk :: ByteString -> ByteString -> ByteString -> ByteString -> IO ByteString
encryptChunk key nonce msg isFinal = throwCryptoErrorIO $ do
    payloadNonce <- nonce12 $ (nonce <> isFinal)
    st <- CC.finalizeAAD <$> CC.initialize key payloadNonce
    let (e, st1) = CC.encrypt msg st
    return $ e <> (convert $ CC.finalize st1)

toRecipient :: X25519Identity -> X25519Recipient
toRecipient (X25519Identity pub _) = X25519Recipient pub

parseRecipient :: Text -> IO X25519Recipient
parseRecipient r = X25519Recipient <$> throwCryptoErrorIO (X25519.publicKey $ b32dec r)


b32 :: (ByteArrayAccess b) => Text -> b -> Text
b32 header b = case Bech32.humanReadablePartFromText header of
        Left e -> T.pack $ show e
        Right header -> case Bech32.encode header (Bech32.dataPartFromBytes (convert b)) of
          Left e  -> T.pack $ show e
          Right t -> t

b32dec :: Text -> ByteString
b32dec r = case Bech32.decode r of
  Left e         -> ""
  Right (hrp, d) -> fromMaybe "" $ Bech32.dataPartToBytes d

-- https://github.com/FiloSottile/age/blob/084c974f5393e5d2776fb1bb3a35eeed271a32fa/x25519.go#L64
mkStanza ::   ByteString -> X25519Recipient -> IO Stanza
mkStanza fileKey (X25519Recipient theirPK) = do
  ourKey <- X25519.generateSecretKey
  let ourPK = X255519.toPublic ourKey
  let shareKey = X25519.dh theirPK ourKey
  let salt  = (convert ourPK) <> (convert theirPK) :: ByteString
  let wrappingKey = hkdf "age-encryption.org/v1/X25519" (convert shareKey) salt
  body <- throwCryptoErrorIO $ do
    nonce <- CC.nonce12 (BS.pack $ take 12 $ repeat 0)
    st0 <- CC.initialize wrappingKey nonce
    let (e, st1) = CC.encrypt fileKey st0
    return $ e <> (convert $ CC.finalize st1)
  pure Stanza {stzType = "X25519", stzBody = body, stzArgs = [encodeBase64Unpadded' (convert ourPK)]}

marshalStanza :: Stanza -> ByteString
marshalStanza stanza =
  let prefix = "-> " :: ByteString
      body = encodeBase64Unpadded' $ stzBody stanza
      argLine = prefix <> stzType stanza <> " " <> intercalate " " (stzArgs stanza) <> "\n"
  in argLine <>
     wrap64b body <> "\n"

mkHeader :: ByteString -> [Stanza] -> ByteString
mkHeader fileKey recipients =
  let intro = "age-encryption.org/v1\n" :: ByteString
      macKey = hkdf "header" fileKey ""
      footer = "---" :: ByteString
      headerNoMac = intro <>  stanza <> footer
      mac = convert (hmac macKey headerNoMac :: HMAC SHA256) :: ByteString
      stanza = BS.concat (marshalStanza <$> recipients)
  in  headerNoMac <> " " <>  (encodeBase64Unpadded' mac) <> "\n"

hkdf :: ByteString -> ByteString -> ByteString -> ByteString
hkdf info key salt = HKDF.expand (HKDF.extract  salt key ::PRK SHA256) info 32

incNonce :: ByteString -> ByteString
incNonce n = BS.pack . snd $ foldr inc1 (True, []) (BS.unpack n)
  where
    inc1  cur (True, acc) = (cur + 1 == 0, (cur + 1) : acc)
    inc1 cur (False, acc) = (False, cur : acc)

zeroNonce :: ByteString
zeroNonce = BS.pack (take 11 $ repeat 0)

wrap64b :: ByteString  -> ByteString
wrap64b bs =
  let (head, tail) = BS.splitAt 64 bs
  in if (BS.length tail == 0) then head
  else head <> "\n" <> wrap64b tail
