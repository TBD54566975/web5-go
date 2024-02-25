# Table of Contents <!-- omit in toc -->

- [Features](#features)
<!-- - [Usage](#usage)
  - [DID Creation](#did-creation)
    - [`did:jwk`](#didjwk)
    - [`did:dht`](#diddht)
    - [`did:web`](#didweb)
  - [DID Resolution](#did-resolution)
  - [Importing / Exporting](#importing--exporting)
    - [Exporting](#exporting)
    - [Importing](#importing) -->
- [Development](#development)
  - [Directory Structure](#directory-structure)
 <!--    - [Rationale](#rationale)
  - [Adding a new DID Method](#adding-a-new-did-method)
    - [Creation](#creation)
    - [Resolution](#resolution) -->


# Features

<!-- * `did:jwk` creation and resolution
* `did:dht` creation and resoluton
* DID Parsing
* `BearerDID` concept.
* `BearerDID` import and export
* All did core spec data structures
* singleton DID resolver -->

> [!NOTE]
> For naming berevity of files, verifiable credential has been shortened to vc. 

# Development

## Directory Structure
```
credentials
├── README.md
├── vc
│   ├── vc.go
│   ├── vc_test.go
│   └── presentation.go (coming soon)
└── vcdatamodel
    ├── credential.go
    ├── credential_test.go
    ├── validators.go
    ├── validators_test.go
    ├── utils.go
    ├── utils_test.go
    ├── presentation.go (coiming soon)
    └── presentation_test.go (coming soon)

```

| package       | description                                                                                         |
| :------------ | :-------------------------------------------------------------------------------------------------- |
| `vc `         | contains _representations_ of a Verifiable credential                                               |
| `vcdatamodel` | contains all of the data models defined in the [VC Data Model](https://www.w3.org/TR/vc-data-model) |