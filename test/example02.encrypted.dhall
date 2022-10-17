let dhall-secret =
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

in  { foo =
      { ageSecret =
          dhall-secret.AgeEncrypted
            { Recipients =
              [ "age1rl8j26etwulmav6yn8p4huu6944n7hsr2pyu2dr0evjzsj2tq92q48arjp"
              , "age1xmcwr5gpzkaxdwz2udww7lht2j4evp4vpl0ujeu64pe5ncpsk9zqhkfw5y"
              ]
            , CiphertextBlob =
                ''
                -----BEGIN AGE ENCRYPTED FILE-----
                YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBFajIrMEFJSlBVYWpYdjBJ
                NU9JYi9nUXY5OGNLVDhuNDI5Rmp5TEFkRFUwCnRJUzh5cGZRNUpOZGRUbi9sQ1lH
                TG5pWnNNWkhaZGZ5NDg1Tnh2bXA1bVUKLT4gWDI1NTE5IHh6UWFQei9ZTDBOaUhS
                UmlDdFBML2xsTXE0a0dOT1RZZSs4KzVTZ0krZ0kKS01XVS96NHh5Zkp1c3FMZEhM
                UHVMR3RCUGkvVGpDK3FsSVBCWGpmRmwyMAotLS0gNjhRUDl2YytSa3hyYktLNzhi
                YkgySGhZQ0JTbnpWS1QxZllBWUZidlpwQQo+ASvjime6wuoah2hCYZvyfNECnGaP
                gNUgQaXch5fgKupqFxT1WD9Rfbk=
                -----END AGE ENCRYPTED FILE-----
                ''
            }
      , plain = "hello world"
      }
    }
