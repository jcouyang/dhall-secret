# dhall-secret

A simple tool to manage secrets in Dhall configuration, inspired by [sops](https://github.com/mozilla/sops)

## Install
download binary according to your OS from release channel, or if you have nix
```
nix-env f https://github.com/jcouyang/dhall-secret/archive/master.tar.gz -iA dhall-secret
```

## Usage

```
dhall-secret --help

Usage: dhall-secret (encrypt | decrypt)

Available options:
-h,--help                Show this help text

Available commands:
encrypt                  encrypt dhall file
decrypt                  decrypt dhall file
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
