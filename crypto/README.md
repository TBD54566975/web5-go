# `crypto`

This package mostly exists to maintain parity with the structure of other web5 SDKs maintainted by TBD. Check out the [dsa](./dsa) package for supported Digital Signature Algorithms

> [!NOTE]
> In the need arises, this package will also contain cryptographic primitives for encryption

# Features 

## Key Manager
[`KeyManager`](./key_manager.go) is an abstraction that can be leveraged to manage/use keys (create, sign etc) as desired per the given use case.

examples of concrete implementations include: AWS KMS, Azure Key Vault, Google Cloud KMS, Hashicorp Vault etc

An In-Memory Key Manager is provided as a reference implementation.

### Usage

> [!WARNING]
> TODO: Fill out. Check out [the tests](./key_manager_test.go) for usage examples in the meanwhile