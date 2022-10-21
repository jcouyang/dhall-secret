# dhall-secret
[![Build and Test](https://github.com/jcouyang/dhall-secret/actions/workflows/build.yml/badge.svg)](https://github.com/jcouyang/dhall-secret/actions/workflows/build.yml)

A simple tool to manage secrets in Dhall configuration, inspired by [sops](https://github.com/mozilla/sops)

## Install

Download binary according to your OS from [releases channel](https://github.com/jcouyang/dhall-secret/releases), or if you have nix

```
nix-env -f https://github.com/jcouyang/dhall-secret/archive/master.tar.gz -iA dhall-secret.components.exes.dhall-secret
```

## Usage

```
Usage: dhall-secret (encrypt | decrypt | gen-types) [-v|--version]

Available options:
-h,--help                Show this help text
-v,--version             print version

Available commands:
encrypt                  Encrypt a Dhall expression
decrypt                  Decrypt a Dhall expression
gen-types                generate types
```

## Example
create a unencrypted version of Dhall file `./test/example.dhall`, put the plain text secret in `PlainText`
```dhall
let dhall-secret =
      https://raw.githubusercontent.com/jcouyang/dhall-secret/38fc27c7da185dda1ddae67c389080154c2336fc/Type.dhall

let empty =
      https://raw.githubusercontent.com/dhall-lang/dhall-lang/v22.0.0/Prelude/Map/empty.dhall

in  { kmsExample =
        dhall-secret.AwsKmsDecrypted
          { KeyId = "alias/dhall-secret/test"
          , PlainText = "a-secret"
          , EncryptionContext = empty Text Text
          }
    , ageSecret =
        dhall-secret.AgeDecrypted
          { Recipients =
            [ "age1rl8j26etwulmav6yn8p4huu6944n7hsr2pyu2dr0evjzsj2tq92q48arjp"
            , "age1xmcwr5gpzkaxdwz2udww7lht2j4evp4vpl0ujeu64pe5ncpsk9zqhkfw5y"
            ]
          , PlainText = "another-secret"
          }
    , somethingElse = "not-secret"
    }

```

The file contains two secrets to be encrypted
- `a-secret` is `dhall-secret.AwsKmsDecrypted` needs to be encrypted via KMS with key id `alias/dhall-secret/test`
- `another-secret` is a `dhall-secret.AgeDecrypted` needs to be encrypted via Age, only who from `Recipients` can decrypt the message.
- `not-a-secret` won't be encrypted

### AWS KMS

1. login to your AWS account, either through `~/.aws/credentials` or `AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY` environment

2. probably need to also `export AWS_REGION=<your-kms-key-region>`

### Age

You will need to export AGE-SECRET-KEY to `DHALL_SECRET_AGE_KEYS` env to decrypt a dhall
```
export DHALL_SECRET_AGE_KEYS=AGE-SECRET-KEY-1GLAZ75TDSSR647WXD0MH3RUU8XGRK6R5SD8UGQ6C6R9MCYR03ULQSUC7D6
dhall-secret decrypt -f ./test/example02.encrypted.dhall
```

or export multiple keys in multiple lines
```
export DHALL_SECRET_AGE_KEYS="AGE-SECRET-KEY-1HKC2ZRPFFY66049G5EWYLT2PMYKTPN6UW6RFEEEN3JEEWTFFFDNQ2QTC8M
AGE-SECRET-KEY-1GLAZ75TDSSR647WXD0MH3RUU8XGRK6R5SD8UGQ6C6R9MCYR03ULQSUC7D6"
dhall-secret decrypt -f ./test/example02.encrypted.dhall
```

you don't need to have the secret key to encrypt the file.

### Encrypt
#### from stdin
```
> dhall-secret encrypt
let dhall-secret =
      https://github.com/jcouyang/dhall-secret/raw/38fc27c7da185dda1ddae67c389080154c2336fc/Type.dhall

in  dhall-secret.AgeDecrypted
      { Recipients =
        [ "age1rl8j26etwulmav6yn8p4huu6944n7hsr2pyu2dr0evjzsj2tq92q48arjp" ]
      , PlainText = "hello age!"
      }
[Ctrl-D]
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

in  dhall-secret.AgeEncrypted
      { Recipients =
        [ "age1rl8j26etwulmav6yn8p4huu6944n7hsr2pyu2dr0evjzsj2tq92q48arjp" ]
      , CiphertextBlob =
          ''
          -----BEGIN AGE ENCRYPTED FILE-----
          YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBMcGt0cEY1TDIyZUszbyt3
          KzFWUHVEY2prUnd3S0RTTzdZMlNaWFJJRkE0CnQ3SG1zWHRnVHlRY3F2dTlDdTEw
          dE1FVElud3RqSG9HN2VlOG1xSGtrUzQKLS0tIGQvazYzc3dCMnN4V0FsRU9sZkQ0
          UnBxVlhBYUtHNkxXR3N5S3NNR0l2WnMKThbkWEbxqbwe+2VSSk5XwtekePESIYE1
          47+XTReJ2UEt6UPqp20XmvKk
          -----END AGE ENCRYPTED FILE-----
          ''
      }
```
#### to stdout
```
> dhall-secret encrypt -f test/example.dhall
```

#### in place
```
dhall-secret encrypt -f test/example.dhall --inplace
```
#### to a new file
```
dhall-secret encrypt -f test/example.dhall -o test/example.encrypted.dhall
```
#### update a encrypted file
```diff
let dhall-secret = ...
in  { foo =
      { aes256 =
          dhall-secret.Aes256Encrypted
            { KeyEnvName = "MY_AES_SECRET"
            , CiphertextBlob = "QBwc5A=="
            , IV = "6HNitzH9f3xf27t99XZa9g=="
            }
      , plain = "hello world"
      }
    }
+  with foo.aes256
+       =
+      dhall-secret.Aes256Decrypted
+        { KeyEnvName = "MY_AES_SECRET", PlainText = "hello AES" }
```
then
```
dhall-secret encrypt -f test/example.dhall -i
```
### Decrypt
#### to stdout
```
> dhall-secret decrypt -f test/example.encrypted.dhall
let dhall-secret = ...
in  { aesExample =
        dhall-secret.Aes256Decrypted
          { KeyEnvName = "MY_AES_SECRET"
          , PlainText = "another secret to be encrypted"
          }
    , kmsExample =
        dhall-secret.AwsKmsDecrypted
          { KeyId =
              "arn:aws:kms:ap-southeast-2:930712508576:key/5d2e1d54-c2e6-49a8-924d-bed828e792ed"
          , PlainText = "a secret to be encrypted"
          , EncryptionContext = [] : List { mapKey : Text, mapValue : Text }
          }
    , somethingElse = "not secret"
    }
```
#### in place
```
dhall-secret decrypt -f test/example.encrypted.dhall --inplace
```
#### to a new file
```
dhall-secret decrypt -f test/example.encrypted.dhall -o test/example.dhall
```
#### plaintext
`--plaintext` will output dhall without types
```
> dhall-secret decrypt -f ./test/example02.encrypted.dhall -p
{ foo =
  { ageSecret =
      dhall-secret.AgeDecrypted
        { Recipients =
          [ "age1rl8j26etwulmav6yn8p4huu6944n7hsr2pyu2dr0evjzsj2tq92q48arjp"
          , "age1xmcwr5gpzkaxdwz2udww7lht2j4evp4vpl0ujeu64pe5ncpsk9zqhkfw5y"
          ]
        , PlainText = "hello age!"
        }
  , plain = "hello world"
  }
}
```
it is very useful when you want to convert it to yaml/json
```
dhall-secret decrypt -f ./test/example02.encrypted.dhall -p | dhall-to-yaml
foo:
  ageSecret: "hello age!"
  plain: hello world
```
### Re-encrypt
```
dhall-secret decrypt -f test/example.encrypted.dhall | dhall-secret encrypt --in-place
```
