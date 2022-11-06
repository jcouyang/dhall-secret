let T = https://oyanglul.us/dhall-secret/Type.dhall

in  { foo =
      { ageSecret =
          T.AgeDecrypted
            { Recipients =
              [ "age1rl8j26etwulmav6yn8p4huu6944n7hsr2pyu2dr0evjzsj2tq92q48arjp"
              , "age1xmcwr5gpzkaxdwz2udww7lht2j4evp4vpl0ujeu64pe5ncpsk9zqhkfw5y"
              ]
            , PlainText = "hello age!"
            }
      , plain = "hello world"
      }
    }
