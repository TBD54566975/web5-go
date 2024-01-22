# `dsa` <!-- omit in toc -->

# Table of Contents <!-- omit in toc -->

- [Summary](#summary)
- [Features](#features)
  - [Key Generation](#key-generation)
    - [Usage](#usage)
  - [Signing](#signing)
    - [Usage](#usage-1)
  - [Verification](#verification)
    - [Usage](#usage-2)


# Summary
This package contains a high-level API that can be used to:
* Generate keys
* Sign data
* Signature integrity verification

The following Digital Signature Algorithms are supported:
* `secp256k1`
* `Ed25519`

> [!NOTE]
> Lower-level APIs are available in the [ecdsa](./ecdsa/) and [eddsa](./eddsa/) packages

# Features

## Key Generation
Generate Private Keys using a specified algorithm

> [!IMPORTANT]
> Keys are returned as JWKs (JSON Web Keys). We chose to do this because JWKs include sufficient metadata about the key that is otherwise lost or stored alongside the key in a bespoke manner

### Usage

> [!WARNING]
> TODO: Fill out. Check out [the tests](./dsa_test.go) for usage examples in the meanwhile


## Signing

Sign a byte payload using the private key provided


### Usage
> [!WARNING]
> TODO: Fill out. Check out [the tests](./dsa_test.go) for usage examples in the meanwhile


## Verification

### Usage
> [!WARNING]
> TODO: Fill out. Check out [the tests](./dsa_test.go) for usage examples in the meanwhile