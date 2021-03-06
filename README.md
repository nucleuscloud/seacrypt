# Seacrypt
CLI and Library used to decrypt secrets with AWS KMS.

# Commands

## exec-env

Used in Nucleus build pipelines to decrypt secrets and mount them in the environment prior to launching the main process.

The keyfile must contain the plaintext contents of the KMS Key Id.

The secrets file must be a flat json file like so:
```json
{
  "MY_KEY": "<base64 encoded encrypted secret>"
}
```

### Usage

You must have a configured AWS config prior to running this command.

The following example decrypt keys and then prints out the environment
```sh
make build
./bin/seacrypt exec-env -k <path-to-keyfile> -f <path-to-secretsfile> "env"
```

Pass `-d` to remove the key from disk afterwards.

# Installation
## Homebrew
You can install seacrypt directly with homebrew

```sh
brew install nucleuscloud/tap/seacrypt
```

## Source
Ensure you have `go` installed.
```sh
make
./bin/seacrypt
```
