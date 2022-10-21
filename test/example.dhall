let dhall-secret =
      https://raw.githubusercontent.com/jcouyang/dhall-secret/38fc27c7da185dda1ddae67c389080154c2336fc/Type.dhall

let empty =
      https://raw.githubusercontent.com/dhall-lang/dhall-lang/v22.0.0/Prelude/Map/empty.dhall

in  { kmsExample =
        dhall-secret.AwsKmsDecrypted
          { KeyId = "alias/dhall-secret/test"
          , PlainText = "a secret to be encrypted"
          , EncryptionContext = empty Text Text
          }
    , ageSecret =
        dhall-secret.AgeDecrypted
          { Recipients =
            [ "age1rl8j26etwulmav6yn8p4huu6944n7hsr2pyu2dr0evjzsj2tq92q48arjp"
            , "age1xmcwr5gpzkaxdwz2udww7lht2j4evp4vpl0ujeu64pe5ncpsk9zqhkfw5y"
            ]
          , PlainText = "hello age!"
          }
    , somethingElse = "not secret"
    }
