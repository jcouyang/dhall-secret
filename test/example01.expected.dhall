{ foo =
  { aws =
    { noContext =
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
        >.AwsKmsDecrypted
          { KeyId =
              "arn:aws:kms:ap-southeast-2:930712508576:key/5d2e1d54-c2e6-49a8-924d-bed828e792ed"
          , PlainText = "hello kms"
          , EncryptionContext = [] : List { mapKey : Text, mapValue : Text }
          }
    , withContext =
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
        >.AwsKmsDecrypted
          { KeyId =
              "arn:aws:kms:ap-southeast-2:930712508576:key/5d2e1d54-c2e6-49a8-924d-bed828e792ed"
          , PlainText = "hello kms with context"
          , EncryptionContext =
            [ { mapKey = "crew", mapValue = "bar" }
            , { mapKey = "environment", mapValue = "prod" }
            ]
          }
    }
  , plain = "hello world"
  }
}
