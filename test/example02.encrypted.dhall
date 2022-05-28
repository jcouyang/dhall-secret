let dhall-secret = ./Type.dhall

in  { foo =
      { aes256 =
          dhall-secret.SymmetricEncrypted
            { Type = < AES256 | ChaChaPoly1305 >.AES256
            , KeyEnvName = "MY_AES_SECRET"
            , CiphertextBlob = "bjw9FZcJynwO"
            , Nonce = "0ZzRkR6CWcYtEqrT"
            , Salt = "uKOAFIXvRbw="
            , Tag = "/8a4FmsqowjXsNRUU+Qvfg=="
            , Context = "context"
            }
      , chacha =
          dhall-secret.SymmetricEncrypted
            { Type = < AES256 | ChaChaPoly1305 >.ChaChaPoly1305
            , KeyEnvName = "MY_AES_SECRET"
            , CiphertextBlob = "4iFSCOWG7X2DMs5D"
            , Nonce = "iDrmCs5wx2DXU+MQ"
            , Salt = "LIHrW8BxM/E="
            , Tag = "auigxG9/Ls6C7cm712gfAA=="
            , Context = "chacha"
            }
      , plain = "hello world"
      }
    }
