module Dhall.Secret
  ( encrypt,
    decrypt,
    secretType,
    defineVar,
    DecryptPreference(..),
  )
where

import           Control.Exception       (throw)
import           Control.Lens
import           Crypto.Cipher.AES       (AES256)
import           Crypto.Cipher.AESGCMSIV (nonce)
import           Crypto.Cipher.Types     (AuthTag (AuthTag, unAuthTag))
import           Crypto.Error            (throwCryptoErrorIO)
import           Crypto.MAC.Poly1305     (Auth (Auth))
import           Data.ByteArray          (ByteArray, ByteArrayAccess, convert)
import           Data.ByteArray.Encoding (Base (Base64), convertFromBase,
                                          convertToBase)
import           Data.ByteString         (ByteString)
import           Data.HashMap.Strict     (HashMap)
import qualified Data.HashMap.Strict     as HashMap
import qualified Data.Text               as T
import qualified Data.Text.Encoding      as T
import qualified Data.Text.IO            as TIO
import qualified Data.Text.Lazy.Encoding as Bytes
import           Data.Void               (Void, vacuous)
import           Dhall                   (Seq, inputExpr, rawInput)
import           Dhall.Core              (Chunks (Chunks), Expr (..),
                                          FieldSelection (FieldSelection),
                                          RecordField (RecordField),
                                          makeBinding, makeFieldSelection,
                                          makeRecordField, normalize,
                                          subExpressions)
import qualified Dhall.Map               as DM
import qualified Dhall.Secret.Aes        as Aes
import qualified Dhall.Secret.Age        as Age
import           Dhall.Secret.Aws        (awsRun)
import qualified Dhall.Secret.Chacha     as Chacha
import           Dhall.Src               (Src)
import           Dhall.TH                (dhall)
import           GHC.Exts                (toList)
import           Network.AWS             (send)
import           Network.AWS.KMS         (decEncryptionContext,
                                          eEncryptionContext)
import qualified Network.AWS.KMS         as KMS
import           Network.AWS.KMS.Decrypt (drsKeyId, drsPlaintext)
import           Network.AWS.KMS.Encrypt (ersCiphertextBlob, ersKeyId)
import           System.Environment      (getEnv)

version :: Expr Src Void
version = [dhall|./version.dhall|]

secretType :: Expr Src Void
secretType = [dhall|./Type.dhall|]

symmetricType :: Expr Src Void
symmetricType = [dhall|./SymmetricType.dhall|]

varName = Var "dhall-secret"
defineVar :: Expr Src Void -> Expr Src Void
defineVar = Let (makeBinding "dhall-secret" secretType)

data DecryptPreference = DecryptPreference
  { dp'notypes :: Bool
  }

encrypt :: Expr Src Void -> IO (Expr Src Void)
encrypt (App (Field u (FieldSelection src t c)) (RecordLit m))
  | u == secretType && t == "AwsKmsDecrypted" = case (DM.lookup "KeyId" m, DM.lookup "PlainText" m, DM.lookup "EncryptionContext" m) of
    ( Just (RecordField _ (TextLit (Chunks _ kid)) _ _),
      Just (RecordField _ (TextLit (Chunks _ pt)) _ _),
      Just ec@(RecordField _ (ListLit _ ecl) _ _)
      ) -> do
        let context = mconcat $ toList (dhallMapToHashMap <$> ecl)
        eResp <- awsRun $ send $ KMS.encrypt kid (T.encodeUtf8 pt) & eEncryptionContext .~ context
        case (eResp ^. ersKeyId, eResp ^. ersCiphertextBlob) of
          (Just kid, Just cb) ->
            pure $
              App
                (Field varName (makeFieldSelection "AwsKmsEncrypted"))
                ( RecordLit $
                    DM.fromList
                      [ ("KeyId", makeRecordField (TextLit (Chunks [] kid))),
                        ("CiphertextBlob", makeRecordField (TextLit (Chunks [] (byteStringToB64 cb)))),
                        ("EncryptionContext", ec)
                      ]
                )
          _ -> error (show eResp)
    _ -> error "Internal Error when encrypting AwsKmsDecrypted expr"
  | u == secretType && t == "AgeDecrypted" = case
      ( DM.lookup "Recipients" m,
        DM.lookup "PlainText" m) of
        (Just (RecordField _ (ListLit _ pks) _ _),
         Just (RecordField _ (TextLit (Chunks _ plaintext)) _ _)) -> do
          rs <- traverse Age.parseRecipient (toList $ extractTextLit <$> pks)
          encrypted <- Age.encrypt rs (T.encodeUtf8 plaintext)
          pure $ App
              (Field varName (makeFieldSelection "AgeEncrypted"))
              ( RecordLit $
                  DM.fromList
                    [ ("Recipients", makeRecordField (ListLit Nothing pks)),
                      ("CiphertextBlob", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 encrypted))))
                    ])
        _ -> error "Internal Error when encrypting Symmetric expr"
  | u == secretType = pure $ App (Field varName (FieldSelection src t c)) (RecordLit m)
encrypt expr = subExpressions encrypt expr

decrypt :: DecryptPreference -> Expr Src Void -> IO (Expr Src Void)
decrypt opts (App (Field u (FieldSelection s t c)) (RecordLit m))
  | u == secretType && t == "AwsKmsEncrypted" = case (DM.lookup "KeyId" m, DM.lookup "CiphertextBlob" m, DM.lookup "EncryptionContext" m) of
    (Just (RecordField _ (TextLit (Chunks _ kid)) _ _), Just (RecordField _ (TextLit (Chunks _ pt)) _ _), Just ec@(RecordField _ (ListLit _ ecl) _ _)) -> do
      eResp <- case convertFromBase Base64 (T.encodeUtf8 pt) of
        Left e -> error (show e)
        Right a -> awsRun $ send $ KMS.decrypt a & decEncryptionContext .~ mconcat (toList (dhallMapToHashMap <$> ecl))
      case (eResp ^. drsKeyId, eResp ^. drsPlaintext) of
        (Just kid, Just pt) ->
          pure $ if dp'notypes opts then
           TextLit (Chunks [] (T.decodeUtf8 pt))
          else
            App
              (Field varName (makeFieldSelection "AwsKmsDecrypted"))
              ( RecordLit $
                  DM.fromList
                    [ ("KeyId", makeRecordField (TextLit (Chunks [] kid))),
                      ("PlainText", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 pt)))),
                      ("Context", ec)
                    ])
        _ -> error (show eResp)
    _ -> error "something wrong decrypting aws kms"
  | u == secretType && t == "AgeEncrypted" = case
      ( DM.lookup "Recipients" m,
        DM.lookup "CiphertextBlob" m) of
        (Just (RecordField _ (ListLit _ pks) _ _),
         Just (RecordField _ (TextLit (Chunks _ plaintext)) _ _)) -> do
          keys <- T.splitOn "\n" . T.pack <$> getEnv "DHALL_SECRET_AGE_KEYS"
          decodedKeys <- traverse Age.parseIdentity keys
          decrypted <- Age.decrypt (T.encodeUtf8 plaintext) decodedKeys
          pure $ App
              (Field varName (makeFieldSelection "AgeDecrypted"))
              ( RecordLit $
                  DM.fromList
                    [ ("Recipients", makeRecordField (ListLit Nothing pks)),
                      ("PlainText", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 decrypted))))
                    ])
        _ -> error "Internal Error when decrypting Age"
  | u == secretType = pure $ App (Field varName (FieldSelection s t c)) (RecordLit m)
decrypt opts expr = subExpressions (decrypt opts) expr

dhallMapToHashMap :: Expr Src a -> HashMap T.Text T.Text
dhallMapToHashMap (RecordLit m) = case (DM.lookup "mapKey" m, DM.lookup "mapValue" m) of
  (Just (RecordField _ (TextLit (Chunks _ k)) _ _), Just (RecordField _ (TextLit (Chunks _ v)) _ _)) -> HashMap.singleton k v
  _ -> mempty
dhallMapToHashMap _ = mempty

b64StringToByteString :: T.Text -> Either String ByteString
b64StringToByteString = convertFromBase Base64 . T.encodeUtf8

byteStringToB64 :: (ByteArrayAccess baa) => baa -> T.Text
byteStringToB64 = T.decodeUtf8 . convertToBase Base64

extractTextLit :: Expr Src Void -> T.Text
extractTextLit (TextLit (Chunks _ t)) = t
extractTextLit _                      = ""
