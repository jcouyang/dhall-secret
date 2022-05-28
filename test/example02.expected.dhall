let dhall-secret =
      < Aes256Decrypted :
          { Context : Text, KeyEnvName : Text, PlainText : Text }
      | Aes256Encrypted :
          { CiphertextBlob : Text
          , Context : Text
          , KeyEnvName : Text
          , Nonce : Text
          , Salt : Text
          , Tag : Text
          }
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

in  { foo =
      { aes256 =
          dhall-secret.Aes256Decrypted
            { KeyEnvName = "MY_AES_SECRET", PlainText = "hello AES" }
      , plain = "hello world"
      }
    }
