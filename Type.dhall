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
| SymmetricDecrypted :
    { Context : Text
    , KeyEnvName : Text
    , PlainText : Text
    , Type : < AES256 | ChaChaPoly1305 >
    }
| SymmetricEncrypted :
    { CiphertextBlob : Text
    , Context : Text
    , KeyEnvName : Text
    , Nonce : Text
    , Salt : Text
    , Tag : Text
    , Type : < AES256 | ChaChaPoly1305 >
    }
>