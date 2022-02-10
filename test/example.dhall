let dhall-secret =
      https://raw.githubusercontent.com/jcouyang/dhall-secret/v0.1.0+6/Type.dhall

let empty =
      https://raw.githubusercontent.com/dhall-lang/dhall-lang/v22.0.0/Prelude/Map/empty.dhall

in  { kmsExample =
        dhall-secret.AwsKmsDecrypted
          { KeyId = "alias/dhall-secret/test"
          , PlainText = "a secret to be encrypted"
          , EncryptionContext = empty Text Text
          }
    , aesExample =
        dhall-secret.Aes256Decrypted
          { KeyEnvName = "MY_AES_SECRET"
          , PlainText = "another secret to be encrypted"
          }
    , somethingElse = "not secret"
    }
