let T = ./Type.dhall

in  { foo =
      { ageSecret =
          T.AgeDecrypted
            { Recipients =
              [ "age125mzp30ssxpeudr9nfcyp4paytxp34950vc828a5grf48lgdrucqx8mar3"
              ]
            , PlainText = "hello age!"
            }
      , plain = "hello world"
      }
    }
