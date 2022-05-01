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
import           Data.ByteArray          (ByteArray)
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
secretType =
  [dhall|
< Aes256Decrypted : { KeyEnvName : Text, PlainText : Text }
| Aes256Encrypted : { CiphertextBlob : Text, IV : Text, KeyEnvName : Text }
| AwsKmsDecrypted :
    { EncryptionContext : List { mapKey : Text, mapValue : Text }
    , KeyId : Text
    , PlainText : Text
    }
| AwsKmsEncrypted :
    { CiphertextBlob : Text
    , EncryptionContext : List { mapKey : Text, mapValue : Text }
    , KeyId : Text
    }
>
|]

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
                        ("CiphertextBlob", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 $ convertToBase Base64 cb)))),
                        ("EncryptionContext", ec)
                      ]
                )
          _ -> error (show eResp)
    _ -> error "Internal Error when encrypting AwsKmsDecrypted expr"
  | u == secretType && t == "Aes256Decrypted" = case (DM.lookup "KeyEnvName" m, DM.lookup "PlainText" m) of
    ( Just ken@(RecordField _ (TextLit (Chunks _ keyEnv)) _ _),
      Just (RecordField _ (TextLit (Chunks _ pt)) _ _)
      ) -> do
        secret <- getEnv (T.unpack keyEnv)
        initIV <- Aes.genRandomIV (undefined :: AES256)
        encrypted <- Aes.encrypt (Aes.mkSecretKey (undefined :: AES256) (T.encodeUtf8 $ T.pack secret)) initIV (T.encodeUtf8 pt)
        pure $
          App
            (Field varName (makeFieldSelection "Aes256Encrypted"))
            ( RecordLit $
                DM.fromList
                  [ ("KeyEnvName", ken),
                    ("CiphertextBlob", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 $ convertToBase Base64 encrypted)))),
                    ("IV", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 $ convertToBase Base64 initIV))))
                  ]
            )
    _ -> error "Internal Error when encrypting Aes256Decrypted expr"
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
                      ("EncryptionContext", ec)
                    ]
              )
        _ -> error (show eResp)
    _ -> error "AwsKmsDecrypted wrong"
  | u == secretType && t == "Aes256Encrypted" = case (DM.lookup "KeyEnvName" m, DM.lookup "CiphertextBlob" m, DM.lookup "IV" m) of
    ( Just ken@(RecordField _ (TextLit (Chunks _ keyEnv)) _ _),
      Just (RecordField _ (TextLit (Chunks _ cb)) _ _),
      Just (RecordField _ (TextLit (Chunks _ iv)) _ _)
      ) -> do
        secret <- getEnv (T.unpack keyEnv)
        initIV <- Aes.mkIV (undefined :: AES256) iv
        decrypted <- case convertFromBase Base64 (T.encodeUtf8 cb) of
          Left e -> error (show e)
          Right cbb -> Aes.decrypt (Aes.mkSecretKey (undefined :: AES256) (T.encodeUtf8 $ T.pack secret)) initIV cbb
        pure $
          App
            (Field varName (makeFieldSelection "Aes256Decrypted"))
            ( RecordLit $
                DM.fromList
                  [ ("KeyEnvName", ken),
                    ("PlainText", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 decrypted))))
                  ]
            )
    _ -> error "AES decrypt wrong"
  | u == secretType = pure $ App (Field varName (FieldSelection s t c)) (RecordLit m)
decrypt opts expr = subExpressions (decrypt opts) expr

dhallMapToHashMap :: Expr Src a -> HashMap T.Text T.Text
dhallMapToHashMap (RecordLit m) = case (DM.lookup "mapKey" m, DM.lookup "mapValue" m) of
  (Just (RecordField _ (TextLit (Chunks _ k)) _ _), Just (RecordField _ (TextLit (Chunks _ v)) _ _)) -> HashMap.singleton k v
  _ -> mempty
dhallMapToHashMap _ = mempty
