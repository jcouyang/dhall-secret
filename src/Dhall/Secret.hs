module Dhall.Secret
  ( encrypt,
    encrypt',
    decrypt,
    DecryptPreference(..),
  )
where

import           Control.Lens
import           Data.ByteArray          (ByteArrayAccess)
import           Data.ByteArray.Encoding (Base (Base64), convertFromBase,
                                          convertToBase)
import           Data.HashMap.Strict     (HashMap)
import qualified Data.HashMap.Strict     as HashMap
import qualified Data.Text               as T
import qualified Data.Text.Encoding      as T
import           Data.Void               (Void)
import           Dhall.Core              (Chunks (Chunks), Expr (..),
                                          FieldSelection (FieldSelection),
                                          RecordField (RecordField),
                                          makeFieldSelection, makeRecordField,
                                          subExpressions, freeIn)
import qualified Dhall.Map               as DM
import qualified Dhall.Secret.Age        as Age
import           Dhall.Secret.Aws        (awsRun)
import           Dhall.Secret.Type       (secretTypes)
import           Dhall.Src               (Src)
import           GHC.Exts                (toList, fromList)
import           Amazonka.KMS.Decrypt         (decrypt_encryptionContext,
                                          )
import qualified Amazonka.KMS         as KMS
import           Amazonka.KMS.Decrypt (decryptResponse_keyId, decryptResponse_plaintext)
import           Amazonka.KMS.Encrypt (encryptResponse_ciphertextBlob, encryptResponse_keyId, encrypt_encryptionContext)
import           System.Environment      (getEnv)

varName :: Expr s a
varName = Var "dhall-secret"

data DecryptPreference = DecryptPreference
  { dp'notypes :: Bool
  }

encrypt :: Expr Src Void -> IO (Expr Src Void)
encrypt = encrypt' []

encrypt' :: [T.Text] -> Expr Src Void -> IO (Expr Src Void)
encrypt' ageRcpOverride (App (Field u (FieldSelection src t c)) (RecordLit m))
  | (u == secretTypes || u == varName ) && t == "AwsKmsDecrypted" = case (DM.lookup "KeyId" m, DM.lookup "PlainText" m, DM.lookup "EncryptionContext" m) of
    ( Just (RecordField _ (TextLit (Chunks _ kid)) _ _),
      Just (RecordField _ (TextLit (Chunks _ pt)) _ _),
      Just ec@(RecordField _ (ListLit _ ecl) _ _)
      ) -> do
        let context = mconcat $ toList (dhallMapToHashMap <$> ecl)
        eResp <- awsRun $ KMS.newEncrypt kid (T.encodeUtf8 pt) & encrypt_encryptionContext ?~ context
        case (eResp ^. encryptResponse_keyId, eResp ^. encryptResponse_ciphertextBlob) of
          (Just _, Just cb) ->
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
  | (u == secretTypes || u == varName ) && t == "AgeDecrypted" = case
      ( DM.lookup "Recipients" m,
        DM.lookup "PlainText" m) of
        (Just (RecordField _ (ListLit _ pks) _ _),
         Just (RecordField _ (TextLit (Chunks _ plaintext)) _ _)) -> do
          let recipients = if null ageRcpOverride then (toList $ extractTextLit <$> pks) else ageRcpOverride
          rs <- traverse Age.parseRecipient recipients
          encrypted <- Age.encrypt rs (T.encodeUtf8 plaintext)
          pure $ App
              (Field varName (makeFieldSelection "AgeEncrypted"))
              ( RecordLit $
                  DM.fromList
                    [ ("Recipients", makeRecordField (ListLit Nothing (fromList $ packTextLit <$> recipients))),
                      ("CiphertextBlob", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 encrypted))))
                    ])
        _ -> error "Internal Error when encrypting Symmetric expr"
  | (u == secretTypes || u == varName) = pure $ App (Field varName (FieldSelection src t c)) (RecordLit m)
encrypt' agerp expr = subExpressions (encrypt' agerp) expr

decrypt :: DecryptPreference -> Expr Src Void -> IO (Expr Src Void)
decrypt opts (App (Field u (FieldSelection s t c)) (RecordLit m))
  | u == secretTypes && t == "AwsKmsEncrypted" = case (DM.lookup "KeyId" m, DM.lookup "CiphertextBlob" m, DM.lookup "EncryptionContext" m) of
    (Just (RecordField _ (TextLit (Chunks _ kid)) _ _), Just (RecordField _ (TextLit (Chunks _ cb)) _ _), Just ec@(RecordField _ (ListLit _ ecl) _ _)) -> do
      eResp <- case convertFromBase Base64 (T.encodeUtf8 cb) of
        Left e -> error (show e)
        Right a -> awsRun $ KMS.newDecrypt a & decrypt_encryptionContext ?~ mconcat (toList (dhallMapToHashMap <$> ecl))
      case (eResp ^. decryptResponse_keyId, eResp ^. decryptResponse_plaintext) of
        (Just _, Just pt) ->
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
  | u == secretTypes && t == "AgeEncrypted" = case
      ( DM.lookup "Recipients" m,
        DM.lookup "CiphertextBlob" m) of
        (Just (RecordField _ (ListLit _ pks) _ _),
         Just (RecordField _ (TextLit (Chunks _ plaintext)) _ _)) -> do
          keys <- T.splitOn "\n" . T.pack <$> getEnv "DHALL_SECRET_AGE_KEYS"
          decodedKeys <- traverse Age.parseIdentity keys
          decrypted <- Age.decrypt (T.encodeUtf8 plaintext) decodedKeys
          pure $ if dp'notypes opts then
            TextLit (Chunks [] (T.decodeUtf8 decrypted))
           else App
              (Field varName (makeFieldSelection "AgeDecrypted"))
              ( RecordLit $
                  DM.fromList
                    [ ("Recipients", makeRecordField (ListLit Nothing pks)),
                      ("PlainText", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 decrypted))))
                    ])
        _ -> error "Internal Error when decrypting Age"
  | u == secretTypes = pure $ App (Field varName (FieldSelection s t c)) (RecordLit m)
decrypt opts expr = subExpressions (decrypt opts) expr

dhallMapToHashMap :: Expr Src a -> HashMap T.Text T.Text
dhallMapToHashMap (RecordLit m) = case (DM.lookup "mapKey" m, DM.lookup "mapValue" m) of
  (Just (RecordField _ (TextLit (Chunks _ k)) _ _), Just (RecordField _ (TextLit (Chunks _ v)) _ _)) -> HashMap.singleton k v
  _ -> mempty
dhallMapToHashMap _ = mempty

byteStringToB64 :: (ByteArrayAccess baa) => baa -> T.Text
byteStringToB64 = T.decodeUtf8 . convertToBase Base64

extractTextLit :: Expr Src Void -> T.Text
extractTextLit (TextLit (Chunks _ t)) = t
extractTextLit _                      = ""

packTextLit :: T.Text -> Expr Src Void
packTextLit t = (TextLit (Chunks [] t))

