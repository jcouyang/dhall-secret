{ foo =
  { bar =
      < AwsKmsDecrypted : { KeyId : Text, PlainText : Text }
      | AwsKmsEncrypted : { CiphertextBlob : Text, KeyId : Text }
      >.AwsKmsEncrypted
        { KeyId = "alias/dhall-secret/test", PlainText = "hello" }
  , tball = "sucks"
  }
}
