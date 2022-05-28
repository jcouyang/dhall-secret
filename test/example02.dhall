let T = ./Type.dhall

in  { foo =
      { aes256 =
          T.SymmetricDecrypted
            { Type = (./SymmetricType.dhall).AES256
            , KeyEnvName = "MY_AES_SECRET"
            , PlainText = "hello AES"
            , Context = "context"
            }
      , chacha =
          T.SymmetricDecrypted
            { Type = (./SymmetricType.dhall).ChaChaPoly1305
            , KeyEnvName = "MY_AES_SECRET"
            , PlainText = "hello Chacha"
            , Context = "chacha"
            }
      , plain = "hello world"
      }
    }
