let Map =
      https://raw.githubusercontent.com/dhall-lang/dhall-lang/v22.0.0/Prelude/Map/Type.dhall

in  < AwsKmsDecrypted :
        { KeyId : Text, PlainText : Text, EncryptionContext : Map Text Text }
    | AwsKmsEncrypted :
        { KeyId : Text
        , CiphertextBlob : Text
        , EncryptionContext : Map Text Text
        }
    | Aes256Decrypted : { KeyEnvName : Text, PlainText : Text }
    | Aes256Encrypted : { KeyEnvName : Text, CiphertextBlob : Text, IV : Text }
    >
