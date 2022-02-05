module Lib
    ( encrypt
    , decrypt
    ) where

import           Aws                     (awsRun)
import           Control.Exception       (throw)
import           Control.Lens
import           Data.ByteArray.Encoding (Base (Base64), convertFromBase,
                                          convertToBase)
import           Data.HashMap.Strict     (HashMap)
import qualified Data.HashMap.Strict     as HashMap
import qualified Data.Text               as T
import qualified Data.Text.Encoding      as T
import qualified Data.Text.Lazy.Encoding as Bytes
import           Data.Void               (Void)
import           Dhall                   (Seq)
import           Dhall.Core              (Chunks (Chunks),
                                          Expr (App, Field, ListLit, RecordLit, TextLit),
                                          FieldSelection (FieldSelection),
                                          RecordField (RecordField),
                                          makeFieldSelection, makeRecordField,
                                          subExpressions)
import qualified Dhall.Map               as DM
import           Dhall.Src               (Src)
import           Dhall.TH                (dhall)
import           GHC.Exts                (toList)
import           Network.AWS             (send)
import           Network.AWS.KMS         (decEncryptionContext,
                                          eEncryptionContext)
import qualified Network.AWS.KMS         as KMS
import           Network.AWS.KMS.Decrypt (drsKeyId, drsPlaintext)
import           Network.AWS.KMS.Encrypt (ersCiphertextBlob, ersKeyId)
secretType :: Expr Src Void
secretType = [dhall|
< AwsKmsDecrypted :
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

encrypt :: Expr Src Void -> IO (Expr Src Void)
encrypt input = do
  subExpressions toEncrypted input
  where
    toEncrypted (App (Field u (FieldSelection _ t _)) (RecordLit m))
      | u == secretType && t == "AwsKmsDecrypted" = case (DM.lookup "KeyId" m, DM.lookup "PlainText" m, DM.lookup "EncryptionContext" m) of
          (Just (RecordField  _ (TextLit (Chunks _ kid)) _ _),
           Just (RecordField _ (TextLit (Chunks _ pt)) _ _),
           Just ec@(RecordField _ (ListLit _ ecl) _ _)) -> do
            let context = mconcat $ toList (dhallMapToHashMap <$> ecl)
            eResp <- awsRun $ send $ KMS.encrypt kid (T.encodeUtf8 pt) & eEncryptionContext .~ context
            case (eResp ^. ersKeyId, eResp ^. ersCiphertextBlob) of
              (Just kid, Just cb) -> pure $ App
                (Field u (makeFieldSelection "AwsKmsEncrypted"))
                (RecordLit $ DM.fromList
                 [ ("KeyId", makeRecordField (TextLit (Chunks [] kid)) )
                 , ("CiphertextBlob", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 $ convertToBase Base64 cb))))
                 , ("EncryptionContext", ec)])
              _ -> error (show eResp)
          _ -> error "AwsKmsDecrypted wrong"
    toEncrypted expr = subExpressions toEncrypted expr

decrypt :: Expr Src Void -> IO (Expr Src Void)
decrypt input = do
  subExpressions toDecrypt input
  where
    toDecrypt (App (Field u (FieldSelection _ t _)) (RecordLit m))
      | u == secretType && t == "AwsKmsEncrypted" = case (DM.lookup "KeyId" m, DM.lookup "CiphertextBlob" m, DM.lookup "EncryptionContext" m) of
          (Just (RecordField  _ (TextLit (Chunks _ kid)) _ _), Just (RecordField _ (TextLit (Chunks _ pt)) _ _), Just ec@(RecordField _ (ListLit _ ecl) _ _)) -> do
            eResp <- case convertFromBase Base64 (T.encodeUtf8 pt) of
              Left e  -> error (show e)
              Right a -> awsRun $ send $ KMS.decrypt a & decEncryptionContext .~ mconcat (toList (dhallMapToHashMap <$> ecl))
            case (eResp ^. drsKeyId, eResp ^. drsPlaintext) of
              (Just kid, Just pt) -> pure $ App
                (Field u (makeFieldSelection "AwsKmsDecrypted"))
                (RecordLit $ DM.fromList
                 [ ("KeyId", makeRecordField (TextLit (Chunks [] kid)) )
                 , ("PlainText", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 pt))))
                 , ("EncryptionContext", ec)])
              _ -> error (show eResp)
          _ -> error "AwsKmsDecrypted wrong"
    toDecrypt expr = subExpressions toDecrypt expr

dhallMapToHashMap :: Expr Src Void -> HashMap T.Text T.Text
dhallMapToHashMap (RecordLit m) = case (DM.lookup "mapKey" m, DM.lookup "mapValue" m) of
  (Just (RecordField _ (TextLit (Chunks _ k)) _ _), Just (RecordField _ (TextLit (Chunks _ v)) _ _)) -> HashMap.singleton k v
  _ -> mempty
dhallMapToHashMap _ = mempty
