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