# web5-go <!-- omit in toc -->

# Table of Contents <!-- omit in toc -->
- [Summary](#summary)
  - [`crypto`](#crypto)
  - [`dids`](#dids)
  - [`jws`](#jws)
  - [`jwt`](#jwt)
- [Development](#development)
  - [Prerequisites](#prerequisites)
    - [`hermit`](#hermit)
    - [Helpful Commands](#helpful-commands)
    - [`web5` CLI](#web5-cli)
    - [Contributing](#contributing)


# Summary
This repo contains the following packages:
| package               | description                                                                                              |
| :-------------------- | :------------------------------------------------------------------------------------------------------- |
| [`crypto`](./crypto/) | Key Generation, signing, verification, and a Key Manager abstraction                                     |
| [`dids`](./dids/)     | DID creation and resolution.                                                                             |
| [`jwk`](./jwk/)       | implements a subset of the [JSON Web Key spec](https://tools.ietf.org/html/rfc7517)                      |
| [`jws`](./jws/)       | [JWS](https://datatracker.ietf.org/doc/html/rfc7515) (JSON Web Signature) signing and verification       |
| [`jwt`](./jwt/)       | [JWT](https://datatracker.ietf.org/doc/html/rfc7519) (JSON Web Token) parsing, signing, and verification |


> [!IMPORTANT]
> Check the README in each directory for more details


## `crypto`
Supported Digital Signature Algorithms:
* [`secp256k1`](https://en.bitcoin.it/wiki/Secp256k1)
* [`Ed25519`](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1)

## `dids`
Supported DID Methods:
* [`did:jwk`](https://github.com/quartzjer/did-jwk/blob/main/spec.md)
* 🚧 [`did:dht`](https://github.com/TBD54566975/did-dht-method) 🚧

## `jws`
JWS signing and verification using DIDs

## `jwt` 
JWT signing and verification using DIDs

# Development

## Prerequisites

### [`hermit`](https://cashapp.github.io/hermit/)
This repo uses hermit to manage all environment dependencies (e.g. `just`, `go`). 

> [!IMPORTANT]
> run `. ./bin/activate-hermit` _everytime_ you enter this directory if you don't have hermit [shell hooks](https://cashapp.github.io/hermit/usage/shell/#shell-hooks) configured

### Helpful Commands

This repo uses [`just`](https://github.com/casey/just) as a command runner. Below is a table of helpful `just` commands:

| command     | description    |
| ----------- | -------------- |
| `just test` | runs all tests |
| `just lint` | runs linter    |

### `web5` CLI

```shell
web5 -h
```

See [cmd/web5/README.md](cmd/web5/README.md) for more information.

### Contributing
Each package's README contains in-depth information about the package's structure and suggestions on how add features specific to that package