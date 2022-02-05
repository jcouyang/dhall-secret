let T = ./Type.dhall

in  { foo =
      { aes256 =
          T.Aes256Decrypted
            { KeyEnvName = "MY_AES_SECRET", PlainText = "hello AES" }
      , plain = "hello world"
      }
    }
