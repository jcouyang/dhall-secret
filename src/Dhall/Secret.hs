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
  | u == secretType && t == "SymmetricDecrypted" = case
      ( DM.lookup "Type" m,
        DM.lookup "KeyEnvName" m,
        DM.lookup "PlainText" m,
        DM.lookup "Context" m) of
        (Just stpe@(RecordField _ (Field symmetricType (FieldSelection _ tpe _)) _ _),
         Just ken@(RecordField _ (TextLit (Chunks _ keyEnv)) _ _),
         Just (RecordField _ (TextLit (Chunks _ pt)) _ _),
         Just (RecordField _ (TextLit (Chunks _ ctx)) _ _)) -> do
          secret <- T.encodeUtf8 . T.pack <$> getEnv (T.unpack keyEnv)
          let (c,p) = (T.encodeUtf8 ctx, T.encodeUtf8 pt)
          case tpe of
            "AES256"         -> do
              (tag, salt, nonce, cb) <- Aes.encrypt secret c p
              pure $ mkSymmetricExpr stpe ken cb nonce salt (unAuthTag tag) ctx
            "ChaChaPoly1305" -> do
              (tag, salt, nonce, cb) <- Chacha.encrypt secret c p
              pure $ mkSymmetricExpr stpe ken cb nonce salt tag ctx
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
    _ -> error "AwsKmsDecrypted wrong"
  | u == secretType && t == "SymmetricEncrypted" = case (DM.lookup "Type" m,
                                                         DM.lookup "KeyEnvName" m,
                                                         DM.lookup "CiphertextBlob" m,
                                                         DM.lookup "Nonce" m,
                                                         DM.lookup "Salt" m,
                                                         DM.lookup "Tag" m,
                                                         DM.lookup "Context" m) of
    ( Just stpe@(RecordField _ (Field symmetricType (FieldSelection _ tpe _)) _ _),
      Just ken@(RecordField _ (TextLit (Chunks _ keyEnv)) _ _),
      Just (RecordField _ (TextLit (Chunks _ cb)) _ _),
      Just (RecordField _ (TextLit (Chunks _ iv)) _ _),
      Just (RecordField _ (TextLit (Chunks _ salt)) _ _),
      Just (RecordField _ (TextLit (Chunks _ tag)) _ _),
      Just (RecordField _ (TextLit (Chunks _ ctx)) _ _)
      ) -> do
        secret <- T.encodeUtf8 . T.pack <$> getEnv (T.unpack keyEnv)
        case traverse b64StringToByteString [iv, salt, tag, cb] of
          Right [iv, s, t, c] -> do
            case tpe of
              "AES256" -> do
                pt <- Aes.decrypt secret (T.encodeUtf8 ctx) c (AuthTag (convert t)) s iv
                pure $ mkSymmetricDecryptedExpr stpe ken pt ctx
              "ChaChaPoly1305" -> do
                pt <- Chacha.decrypt secret (T.encodeUtf8 ctx) c (Auth (convert t)) s iv
                pure $ mkSymmetricDecryptedExpr stpe ken pt ctx
          Left e    -> error (show e)
    _ -> error "Symmetric decrypt wrong"
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

mkSymmetricExpr tpe ken cb nonce salt tag ctx = App
            (Field varName (makeFieldSelection "SymmetricEncrypted"))
            ( RecordLit $
                DM.fromList
                  [ ("Type",tpe),
                    ("KeyEnvName", ken),
                    ("CiphertextBlob", makeRecordField (TextLit (Chunks [] (byteStringToB64 cb)))),
                    ("Nonce", makeRecordField (TextLit (Chunks [] (byteStringToB64 nonce)))),
                    ("Salt", makeRecordField (TextLit (Chunks [] (byteStringToB64 salt)))),
                    ("Tag", makeRecordField (TextLit (Chunks [] (byteStringToB64 tag)))),
                    ("Context", makeRecordField (TextLit (Chunks [] ctx)))
                  ]
            )

mkSymmetricDecryptedExpr tpe ken pt ctx =       App
            (Field varName (makeFieldSelection "SymmetricDecrypted"))
            ( RecordLit $
                DM.fromList
                  [ ("Type", tpe),
                    ("KeyEnvName", ken),
                    ("Context", makeRecordField (TextLit (Chunks [] ctx))),
                    ("PlainText", makeRecordField (TextLit (Chunks [] ((T.decodeUtf8 . convert) pt))))
                  ]
            )
