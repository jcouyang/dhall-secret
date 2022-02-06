{ foo =
  { aes256 =
      < Aes256Decrypted : { KeyEnvName : Text, PlainText : Text }
      | Aes256Encrypted :
          { CiphertextBlob : Text, IV : Text, KeyEnvName : Text }
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
      >.Aes256Decrypted
        { KeyEnvName = "MY_AES_SECRET", PlainText = "hello AES" }
  , plain = "hello world"
  }
}
