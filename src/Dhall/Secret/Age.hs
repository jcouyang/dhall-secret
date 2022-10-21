module Dhall.Secret.Age
  ( encrypt,
    decrypt,
    generateX25519Identity,
    parseRecipient,
    parseIdentity,
    toRecipient
  ) where
import qualified Codec.Binary.Bech32          as Bech32
import qualified Crypto.Cipher.ChaChaPoly1305 as CC
import           Crypto.Cipher.Types          (Cipher (cipherInit))
import           Crypto.Error                 (CryptoError (..),
                                               CryptoFailable (..),
                                               eitherCryptoError,
                                               throwCryptoErrorIO)
import           Crypto.Hash                  (SHA256)
import           Crypto.KDF.HKDF              (PRK)
import qualified Crypto.KDF.HKDF              as HKDF
import           Crypto.MAC.HMAC              (HMAC (HMAC), hmac)
import qualified Crypto.PubKey.Curve25519     as X25519
import           Crypto.Random                (MonadRandom (getRandomBytes))
import           Data.ByteArray               (ByteArray, ByteArrayAccess,
                                               Bytes, convert, pack)
import           Data.ByteArray.Encoding      (Base (Base64, Base64URLUnpadded),
                                               convertToBase)
import           Data.ByteString              (ByteString, empty, intercalate)
import qualified Data.ByteString              as BS
import qualified Data.ByteString.Base64       as BS
import           Data.Either                  (isRight)
import           Data.List                    (find, reverse)
import           Data.Maybe                   (fromMaybe)
import           Data.PEM                     (PEM (..), pemParseBS, pemWriteBS)
import           Data.Text                    (Text)
import qualified Data.Text                    as T
import qualified Data.Text.Encoding           as TE

data Stanza = Stanza
  { stzType:: ByteString
  , stzArgs :: [ByteString]
  , stzBody :: ByteString
  } deriving Show
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
  body <-  encryptChunks (payloadKey nonce fileKey) (zeroNonceOf 11) msg
  pure $ pemWriteBS $ PEM { pemName ="AGE ENCRYPTED FILE", pemHeader = [], pemContent = mkHeader fileKey stanzas <> nonce <> body}

decrypt :: ByteString -> [X25519Identity] -> IO ByteString
decrypt ciphertext identities = do
  (Cipher header nonce body) <- either error pure $ parseCipher ciphertext
  let Header stz mac = header
  let possibleKeys = findFileKey identities header
  case find isRight $ possibleKeys of
    Just (Right key) -> do
      let (headerNoMac, macGot) = mkHeaderMac key stz
      if macGot == mac then
        decryptChunks (payloadKey nonce key) (zeroNonceOf 11) body
      else error $ show $  "Header MAC not match" <> headerNoMac <> "\n" <> macGot
    _                -> error "No file key found"

generateX25519Identity :: IO X25519Identity
generateX25519Identity = do
  sec <- X25519.generateSecretKey
  pure $ X25519Identity (X25519.toPublic sec) sec

parseRecipient :: Text -> IO X25519Recipient
parseRecipient r = X25519Recipient <$> throwCryptoErrorIO (X25519.publicKey $ b32dec r)

parseIdentity :: Text -> IO X25519Identity
parseIdentity i = throwCryptoErrorIO $ do
  key <- X25519.secretKey (b32dec i)
  pure $ X25519Identity (X25519.toPublic key) key

decryptChunks :: ByteString -> ByteString -> ByteString -> IO ByteString
decryptChunks key nonce body = case BS.splitAt (64 * 1024) body of
  (head, tail) | tail == BS.empty -> decryptChunk key nonce head (BS.pack [1])
  (head, tail)                    -> decryptChunk key nonce head (BS.pack [0]) <> decryptChunks key (incNonce nonce) tail

decryptChunk :: ByteString -> ByteString -> ByteString -> ByteString -> IO ByteString
decryptChunk key nonce cipherblob isFinal = do
    st1 <- throwCryptoErrorIO $ do
      payloadNonce <- CC.nonce12 $ (nonce <> isFinal)
      CC.finalizeAAD  <$> CC.initialize key payloadNonce
    let (msg, tag) = BS.splitAt (BS.length cipherblob - 16) cipherblob
    let (d, st2) = CC.decrypt msg st1
    let authtag = CC.finalize st2
    if (convert authtag) == tag then pure d else error "Invalid auth tag"

parseCipher :: ByteString -> Either String CipherBlock
parseCipher ct = do
  content <- pemContent . head <$> pemParseBS ct
  let (v1line, rest) = BS.break (== 0x0a) content
  (header, rest2) <- parseHeader (Header [] "") (BS.drop 1 rest)
  let (nonce, body) = BS.splitAt 16 rest2
  pure $ Cipher header nonce body

parseHeader :: Header ->  ByteString -> Either String (Header, ByteString)
parseHeader (Header stz mac) content = do
  case BS.take 3 content of
    "---" ->
      let (mac, body) = BS.break isLF $ content in
        Right $ (Header (reverse stz) (BS.decodeBase64Lenient $ BS.drop 4 mac), BS.drop 1 body)
    "-> " ->
      let (recipients, rest1) = BS.break isLF $ BS.drop 3 content
          (fileKey, rest2) = BS.break isLF $ BS.drop 1 rest1
          (stztype, rest11) = BS.break isSpace recipients
          stzarg = BS.drop 1 rest11
          st = Stanza {stzType = stztype, stzArgs = [stzarg], stzBody = BS.decodeBase64Lenient fileKey} in
      parseHeader (Header (st:stz) mac) (BS.drop 1 rest2)
    _ -> Left "invalid headers"
  where
    isLF = (== 0x0a)
    isSpace = (== 0x20)

findFileKey :: [X25519Identity] -> Header -> [Either CryptoError ByteString]
findFileKey identities (Header stz mac) = hasKey <$> identities <*> stz
  where
    hasKey :: X25519Identity -> Stanza -> Either CryptoError ByteString
    hasKey (X25519Identity pk sec) stz = eitherCryptoError $ do
      let theirPkBs = BS.decodeBase64Lenient $ head (stzArgs stz)
      theirPk <- X25519.publicKey theirPkBs
      let shareKey = X25519.dh theirPk sec
      let salt = (convert theirPk) <> (convert pk)
      let wrappingKey = hkdf "age-encryption.org/v1/X25519" (convert shareKey) salt
      nonce <- CC.nonce12 (zeroNonceOf 12)
      st0 <- CC.initialize wrappingKey nonce
      let fileKey = stzBody stz
      let (e, tag) = BS.splitAt (BS.length fileKey - 16) fileKey
      let (d, st1) = CC.decrypt e st0
      let dtag = CC.finalize st1
      if (convert dtag) == tag then pure d else CryptoFailed CryptoError_AuthenticationTagSizeInvalid

encryptChunks :: ByteString -> ByteString -> ByteString -> IO ByteString
encryptChunks key nonce msg = case BS.splitAt (64 * 1024) msg of
  (head, tail) | tail == BS.empty -> encryptChunk key nonce head (BS.pack [1])
  (head, tail)                    -> encryptChunk key nonce head (BS.pack [0]) <> encryptChunks key (incNonce nonce) tail

encryptChunk :: ByteString -> ByteString -> ByteString -> ByteString -> IO ByteString
encryptChunk key nonce msg isFinal = do
  st <- throwCryptoErrorIO $ do
    payloadNonce <- CC.nonce12 $ (nonce <> isFinal)
    CC.finalizeAAD <$> CC.initialize key payloadNonce
  let (e, st1) = CC.encrypt msg st
  let tag = CC.finalize st1
  return $ e <> (convert tag)

toRecipient :: X25519Identity -> X25519Recipient
toRecipient (X25519Identity pub _) = X25519Recipient pub

b32 :: (ByteArrayAccess b) => Text -> b -> Text
b32 header b = case Bech32.humanReadablePartFromText header of
        Left e -> T.pack $ show e
        Right header -> case Bech32.encode header (Bech32.dataPartFromBytes (convert b)) of
          Left e  -> T.pack $ show e
          Right t -> t

b32dec :: Text -> ByteString
b32dec r = case Bech32.decode r of
  Left e         -> error "Cannot decode bech32"
  Right (hrp, d) -> fromMaybe (error "Cannot extract bech32 data") $ Bech32.dataPartToBytes d

mkStanza ::   ByteString -> X25519Recipient -> IO Stanza
mkStanza fileKey (X25519Recipient theirPK) = do
  ourKey <- X25519.generateSecretKey
  let ourPK = X25519.toPublic ourKey
  let shareKey = X25519.dh theirPK ourKey
  let salt  = (convert ourPK) <> (convert theirPK) :: ByteString
  let wrappingKey = hkdf "age-encryption.org/v1/X25519" (convert shareKey) salt
  body <- throwCryptoErrorIO $ do
    nonce <- CC.nonce12 (BS.pack $ take 12 $ repeat 0)
    st0 <- CC.initialize wrappingKey nonce
    let (e, st1) = CC.encrypt fileKey st0
    return $ e <> (convert $ CC.finalize st1)
  pure Stanza {stzType = "X25519", stzBody = body, stzArgs = [BS.encodeBase64Unpadded' (convert ourPK)]}

marshalStanza :: Stanza -> ByteString
marshalStanza stanza =
  let prefix = "-> " :: ByteString
      body = BS.encodeBase64Unpadded' $ stzBody stanza
      argLine = prefix <> stzType stanza <> " " <> intercalate " " (stzArgs stanza) <> "\n"
  in argLine <>
     wrap64b body <> "\n"

mkHeader :: ByteString -> [Stanza] -> ByteString
mkHeader fileKey recipients =
  let (headerNoMac, mac) = mkHeaderMac fileKey recipients
  in  headerNoMac <> " " <>  (BS.encodeBase64Unpadded' mac) <> "\n"

mkHeaderMac fileKey recipients =
  let intro = "age-encryption.org/v1\n" :: ByteString
      macKey = hkdf "header" fileKey ""
      footer = "---" :: ByteString
      stanza = BS.concat (marshalStanza <$> recipients)
      headerNoMac = intro <>  stanza <> footer
      mac = convert (hmac macKey headerNoMac :: HMAC SHA256) :: ByteString
  in (headerNoMac, mac)

hkdf :: ByteString -> ByteString -> ByteString -> ByteString
hkdf info key salt = HKDF.expand (HKDF.extract  salt key ::PRK SHA256) info 32

incNonce :: ByteString -> ByteString
incNonce n = BS.pack . snd $ foldr inc1 (True, []) (BS.unpack n)
  where
    inc1  cur (True, acc) = (cur + 1 == 0, (cur + 1) : acc)
    inc1 cur (False, acc) = (False, cur : acc)

zeroNonceOf :: Int -> ByteString
zeroNonceOf n = BS.pack (take n $ repeat 0)

wrap64b :: ByteString  -> ByteString
wrap64b bs =
  let (head, tail) = BS.splitAt 64 bs
  in if (BS.length tail == 0) then head
  else head <> "\n" <> wrap64b tail

payloadKey :: ByteString -> ByteString -> ByteString
payloadKey nonce filekey = HKDF.expand (HKDF.extract  nonce filekey ::PRK SHA256) ("payload" :: ByteString) 32
