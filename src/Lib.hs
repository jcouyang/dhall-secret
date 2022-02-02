module Lib
    ( encrypt
    , decrypt
    ) where

import           Aws                     (awsRun)
import           Control.Exception       (throw)
import           Control.Lens            ((^.))
import           Data.ByteArray.Encoding
import qualified Data.Text               as T
import qualified Data.Text.Encoding      as T
import qualified Data.Text.Lazy.Encoding as Bytes
import           Data.Void               (Void)
import           Dhall
import           Dhall.Core
import qualified Dhall.Map               as DM
import           Dhall.Src               (Src)
import           Dhall.TH
import           Network.AWS             (send)
import qualified Network.AWS.KMS         as KMS
import           Network.AWS.KMS.Decrypt (drsKeyId, drsPlaintext)
import           Network.AWS.KMS.Encrypt (ersCiphertextBlob, ersKeyId)

secretType :: Expr Src Void
secretType = [dhall|
< AwsKmsDecrypted : { KeyId : Text, PlainText : Text }
| AwsKmsEncrypted : { KeyId : Text, CiphertextBlob : Text }
>|]

encrypt :: Expr Src Void -> IO (Expr Src Void)
encrypt input = do
  subExpressions toEncrypted input
  where
    toEncrypted (App (Field u (FieldSelection _ t _)) (RecordLit m))
      | u == secretType && t == "AwsKmsDecrypted" = case (DM.lookup "KeyId" m, DM.lookup "PlainText" m) of
          (Just (RecordField  _ (TextLit (Chunks _ kid)) _ _), Just (RecordField _ (TextLit (Chunks _ pt)) _ _)) -> do
            eResp <- awsRun $ send $ KMS.encrypt kid (T.encodeUtf8 pt)
            case (eResp ^. ersKeyId, eResp ^. ersCiphertextBlob) of
              (Just kid, Just cb) -> pure $ App
                (Field u (makeFieldSelection "AwsKmsEncrypted"))
                (RecordLit $ DM.fromList
                 [ ("KeyId", makeRecordField (TextLit (Chunks [] kid)) )
                 , ("CiphertextBlob", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 $ convertToBase Base64 cb))))])
              _ -> error (show eResp)
          _ -> error "AwsKmsDecrypted wrong"
    toEncrypted expr = subExpressions toEncrypted expr

decrypt :: Expr Src Void -> IO (Expr Src Void)
decrypt input = do
  subExpressions toDecrypt input
  where
    toDecrypt (App (Field u (FieldSelection _ t _)) (RecordLit m))
      | u == secretType && t == "AwsKmsEncrypted" = case (DM.lookup "KeyId" m, DM.lookup "CiphertextBlob" m) of
          (Just (RecordField  _ (TextLit (Chunks _ kid)) _ _), Just (RecordField _ (TextLit (Chunks _ pt)) _ _)) -> do
            eResp <- case convertFromBase Base64 (T.encodeUtf8 pt) of
              Left e  -> error (show e)
              Right a -> awsRun $ send $ KMS.decrypt a
            case (eResp ^. drsKeyId, eResp ^. drsPlaintext) of
              (Just kid, Just cb) -> pure $ App
                (Field u (makeFieldSelection "AwsKmsDecrypted"))
                (RecordLit $ DM.fromList
                 [ ("KeyId", makeRecordField (TextLit (Chunks [] kid)) )
                 , ("PlainText", makeRecordField (TextLit (Chunks [] (T.decodeUtf8 cb))))])
              _ -> error (show eResp)
          _ -> error "AwsKmsDecrypted wrong"
    toDecrypt expr = subExpressions toDecrypt expr
