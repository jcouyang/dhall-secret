# dhall-secret
[![Build and Test](https://github.com/jcouyang/dhall-secret/actions/workflows/build.yml/badge.svg)](https://github.com/jcouyang/dhall-secret/actions/workflows/build.yml)

A simple tool to manage secrets in Dhall configuration, inspired by [sops](https://github.com/mozilla/sops)

## Install

Download binary according to your OS from [releases channel](https://github.com/jcouyang/dhall-secret/releases), or if you have nix

```
nix-env -f https://github.com/jcouyang/dhall-secret/archive/master.tar.gz -iA dhall-secret
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
      https://raw.githubusercontent.com/jcouyang/dhall-secret/v0.1.8/Type.dhall

let empty =
      https://raw.githubusercontent.com/dhall-lang/dhall-lang/v22.0.0/Prelude/Map/empty.dhall

in  { kmsExample =
        dhall-secret.AwsKmsDecrypted
          { KeyId = "alias/dhall-secret/test"
          , PlainText = "a secret to be encrypted"
          , EncryptionContext = empty Text Text
          }
    , aesExample =
        dhall-secret.Aes256Decrypted
          { KeyEnvName = "MY_AES_SECRET"
          , PlainText = "another secret to be encrypted"
          }
    , somethingElse = "not secret"
    }
```

The file contains two secrets to be encrypted
- `a secret to be encrypted` is a secret needs to be encrypted via KMS with key id `alias/dhall-secret/test`
- `another secret to be encrypted` is a secret needs to be encrypted via AES256, the secret string of AES encryption need to be provide in environment vairable `MY_AES_SECRET`

### AWS KMS

1. login to your AWS account, either through `~/.aws/credentials` or `AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY` environment

2. probably need to also `export AWS_REGION=<your-kms-key-region>`

### AES256

just export the secret string in environment variable that matching the name in `KeyEnvName`
```
export MY_AES_SECRET=super-secure-secret
```

### Encrypt
#### from stdin
```
> dhall-secret encrypt
let dhall-secret =
      https://raw.githubusercontent.com/jcouyang/dhall-secret/v0.1.0+6/Type.dhall

in  { my-config =
        dhall-secret.Aes256Decrypted
          { KeyEnvName = "MY_AES_SECRET", PlainText = "shhhh" }
    }
[Ctrl-D]
let dhall-secret = ...

in  dhall-secret.Aes256Encrypted
      { KeyEnvName = "MY_AES_SECRET"
      , CiphertextBlob = "Um5EXmk="
      , IV = "CdbCJEEk2B8/e2YWTNvMtg=="
      }
```
#### to stdout
```
> dhall-secret encrypt -f test/example.dhall
let dhall-secret = ...

in  { aesExample =
        dhall-secret.Aes256Encrypted
          { KeyEnvName = "MY_AES_SECRET"
          , CiphertextBlob = "LxjbrUXYPyUyL3Zs/2e0D+2ERuUl6feqZsAKA8GA"
          , IV = "vMAEGQmmBzw71yTdnIfqDg=="
          }
    , kmsExample =
        dhall-secret.AwsKmsEncrypted
          { KeyId =
              "arn:aws:kms:ap-southeast-2:930712508576:key/5d2e1d54-c2e6-49a8-924d-bed828e792ed"
          , CiphertextBlob =
              "AQICAHi57hQGRM9IFIHoHuk+WakSY0atAV9FXc+z5HouBxa8MAHG1oF/3MNJF3tNIaYnKiFrAAAAdjB0BgkqhkiG9w0BBwagZzBlAgEAMGAGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMI0avfHdpPID2SGr8AgEQgDPAVWUzh7vyhloh3ij/BOS4/jIr/4mvyyJ7Nx0XmM1BlE0NQReINgv+Gpu47U15qq6hHS0="
          , EncryptionContext = [] : List { mapKey : Text, mapValue : Text }
          }
    , somethingElse = "not secret"
    }
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

### Re-encrypt
```
dhall-secret decrypt -f test/example.encrypted.dhall | dhall-secret encrypt --in-place
```
