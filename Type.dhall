< AgeDecrypted : { PlainText : Text, Recipients : List Text }
| AgeEncrypted : { CiphertextBlob : Text, Recipients : List Text }
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