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
| AgeDecrypted : { Recipients : List Text, PlainText : Text }
| AgeEncrypted : { Recipients : List Text, CiphertextBlob : Text }
>
