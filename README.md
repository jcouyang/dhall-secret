# dhall-secret
[![Build and Test](https://github.com/jcouyang/dhall-secret/actions/workflows/build.yml/badge.svg)](https://github.com/jcouyang/dhall-secret/actions/workflows/build.yml)

A simple tool to manage secrets in Dhall configuration, inspired by [sops](https://github.com/mozilla/sops)

## Install

Download binary according to your OS from [releases channel](https://github.com/jcouyang/dhall-secret/releases), or if you have nix

```
nix-env f https://github.com/jcouyang/dhall-secret/archive/master.tar.gz -iA dhall-secret
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
### Create the unencrypted expression
assuming you have a Dhall file `./test/example01.dhall`
```dhall
let T = https://raw.githubusercontent.com/jcouyang/dhall-secret/v0.1.0+4/Type.dhall

let empty =
      https://raw.githubusercontent.com/dhall-lang/dhall-lang/v22.0.0/Prelude/Map/empty.dhall

in  { foo =
      { aws =
        { noContext =
            T.AwsKmsDecrypted
              { KeyId = "alias/dhall-secret/test"
              , PlainText = "hello kms"
              , EncryptionContext = empty Text Text
              }
        , withContext =
            T.AwsKmsDecrypted
              { KeyId = "alias/dhall-secret/test"
              , PlainText = "hello kms with context"
              , EncryptionContext = toMap { crew = "bar", environment = "prod" }
              }
        }
      , plain = "hello world"
      }
    }
```

### AWS KMS

1. login to your AWS account, either through `~/.aws/credentials` or `AWS_ACCESS_KEY_ID/SECRET` environment

2. update the example file `./test/example01.dhall` with your KMS key id

3. probably need `export AWS_REGION=<your-kms-key-region>` depends whichever authentication method you choosed from step 1

```
dhall-secret encrypt -f test/example01.dhall
```

by default it will output to stdout, unless an output filename is provided

```
dhall-secret encrypt -f test/example01.dhall -o test/example01.encrypted.dhall
```

or replace the input file inplace

```
dhall-secret encrypt -f test/example01.dhall
```

`test/example01.dhall` will be replace with the encrypted and normalized version.

### AES256

AES256 is much simpler to use comparing with KMS, but you will need to manage your secret string carefully on your own.

just export the secret string in environment variable that matching the name in `KeyEnvName`

```
export MY_AES_SECRET=super-secure-secret
dhall-secret encrypt -f test/example02.dhall
```

### Re-encrypt
```
dhall-secret decrypt -f test/examples01.encrypted.dhall | dhall-secret encrypt --in-place
```
