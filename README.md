# dhall-secret
[![Build and Test](https://github.com/jcouyang/dhall-secret/actions/workflows/build.yml/badge.svg)](https://github.com/jcouyang/dhall-secret/actions/workflows/build.yml)

A simple tool to manage secrets in Dhall configuration, inspired by [sops](https://github.com/mozilla/sops)

## Install
### nix
```
nix-env -f https://github.com/jcouyang/dhall-secret/archive/master.tar.gz -iA dhall-secret.components.exes.dhall-secret
```

### binary
Download binary according to your OS from [releases channel](https://github.com/jcouyang/dhall-secret/releases)

### docker
docker images are avail [here](https://github.com/jcouyang/dhall-secret/pkgs/container/dhall-secret)
```
docker run ghcr.io/jcouyang/dhall-secret:latest
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
let empty =
      https://prelude.dhall-lang.org/Map/empty

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
#### from stdin to stdout
```
> dhall-secret encrypt
dhall-secret.AgeDecrypted
  { Recipients =
    [ "age1rl8j26etwulmav6yn8p4huu6944n7hsr2pyu2dr0evjzsj2tq92q48arjp" ]
    , PlainText = "hello age!"
  }
[Ctrl-D]
let dhall-secret =
      https://raw.githubusercontent.com/jcouyang/dhall-secret/master/Type.dhall
        sha256:d7b55a2f433e19cf623d58c339346a604d96989f60cffdecee125a504a068dc9

in  dhall-secret.AgeEncrypted
      { Recipients =
        [ "age1rl8j26etwulmav6yn8p4huu6944n7hsr2pyu2dr0evjzsj2tq92q48arjp" ]
      , CiphertextBlob =
          ''
          -----BEGIN AGE ENCRYPTED FILE-----
          YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBEUHJPRnJzV2JVL2VKTDE3
          VFpOVFZqOHhIMlhsNCtrNjQ4ZU95cjQ1T25rCk42cFBjcVRUV3ZZYkd0dUxBakN6
          YVNzY1k5WEtNRUJNbjI5YUs3RThlQWcKLS0tIHNObWFIZW9MR2FsekQwY0dyZ3hF
          VmdVYzVGRDRDUWFzWTN3N3RGRWVCbG8KSwwDZ5d+O1w0U8AQB4TRdbA7V20dk2kk
          5P1QNjxYMEyHyJKiijRyltq+
          -----END AGE ENCRYPTED FILE-----
          ''
      }
```

#### encrypt file in place
```
dhall-secret encrypt -f test/example.dhall --inplace
```
#### to a new file
```
dhall-secret encrypt -f test/example.dhall -o test/example.encrypted.dhall
```
#### update a encrypted file
you can update a encrypted file with dhall expr without needing to decrypt the file
```
dhall-secret encrypt <<< './test/example02.dhall with plain = dhall.AgeDecrypted {PlainText = "not plain any more", Recipients = ["age1xmcwr5gpzkaxdwz2udww7lht2j4evp4vpl0ujeu64pe5ncpsk9zqhkfw5y"]}'
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
`--plain-text` will output dhall without types
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
