let T = ./Type.dhall

in  { foo.bar
      =
        T.AwsKmsDecrypted
          { KeyId = "alias/dhall-secret/test", PlainText = "hello" }
    }
