let T = ./Type.dhall

let empty =
      https://raw.githubusercontent.com/dhall-lang/dhall-lang/v22.0.0/Prelude/Map/empty.dhall

in  { foo =
      { aws =
        { noContext =
            T.AwsKmsDecrypted
              { KeyId = "alias/dhall-secret/test"
              , PlainText = "hello kms"
              , EncryptionContext = empty Text Text
              }
        , withContext =
            T.AwsKmsDecrypted
              { KeyId = "alias/dhall-secret/test"
              , PlainText = "hello kms with context"
              , EncryptionContext = toMap { crew = "bar", environment = "prod" }
              }
        }
      , plain = "hello world"
      }
    }
