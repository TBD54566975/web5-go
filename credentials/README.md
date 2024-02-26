# Table of Contents <!-- omit in toc -->

- [Features](#features)
- [Usage](#usage)
  - [Verifiable Credentials](#vc)
    - [`Create`](#vccreate)
    - [`Sign`](#vcsign)
    - [`Verify`](#vcverify)
- [Development](#development)
  - [Directory Structure](#directory-structure)
 <!--    - [Rationale](#rationale)
  - [Adding a new DID Method](#adding-a-new-did-method)
    - [Creation](#creation)
    - [Resolution](#resolution) -->


# Features

* `VerifiableCredential` creation, signing and verifying

> [!NOTE]
> This packges uses the term VC to refere to a Verifiable Credential for berevity

# Usage

## Verifiable Credential Creation

### `CreateCredentialOptions`

```
import (
    "github.com/tbd54566975/web5-go/credentials/vc"
    vcdm "github.com/tbd54566975/web5-go/credentials/vcdatamodel"
)

func main() {
  types := []vcdm.URI{"VerifiableCredential", "UniversityDegreeCredential"}
  issuer := "https://example.edu"

  // IDString is a built in type for a subject which is just a DID, but any type
  // which implements `vcdm.CredentialSubject` may be used here
  subjectID := vcdm.IDString("did:example:ebfeb1f712ebc6f1c276e12ec21")
  issuanceDate := "2010-01-01T19:23:24Z"
  expirationDate := "2039-12-31T19:23:24Z"

  o := vc.CreateCredentialOptions{
		Type:         types,
		Issuer:         issuer,
		Subject:        []vcdm.CredentialSubject{subjectID},
		IssuanceDate:   issuanceDate,
		ExpirationDate: expirationDate,
	}

	var vc vc.VerifiableCredential
	err := vc.Create(o)
}
```
> [!Warning]
> `Issuer` and `Subject` are both required fields in order to run `Create`. It is not recommended to create a 
> Verifialbe Credential without using `CreateCredentialOptions`

> [!Warning]
> `Context` must contain the default context (*"https://www.w3.org/2018/credentials/v1"*). This value 
can be accessed directly from the `vcdatamodel` package (`vcdatamodel.DefaultCredsContext`)

> [!Warning]
> `Type` must contain the *"VerifiableCredential"* type. This value can be accessed directly from the 
> `vcdatamodel` package (`vcdatamodel.DefaultVCType`)

You can also create the Verifiable Credential directly from the `CreateCredentialOptions`:

```
import (
    "github.com/tbd54566975/web5-go/credentials/vc"
    vcdm "github.com/tbd54566975/web5-go/credentials/vcdatamodel"
)

func main() {
  types := []string{"VerifiableCredential", "UniversityDegreeCredential"}
  issuer := "https://example.edu"
  subjectID := vcdm.IDString("did:example:ebfeb1f712ebc6f1c276e12ec21")
  issuanceDate := "2010-01-01T19:23:24Z"
  expirationDate := "2039-12-31T19:23:24Z"

  o := vc.CreateCredentialOptions{
		Type:         types,
		Issuer:         issuer,
		Subject:        []vcdm.CredentialSubject{subjectID},
		IssuanceDate:   issuanceDate,
		ExpirationDate: expirationDate,
	}

	vc, err := o.CreateVerifiableCredential()
}
```
> [!NOTE]
> If no `IssuanceDate` is provided, a string representing the current date-time will be added for you.

## Signing

`Sign(signVCOpt *SignVCOptions) (string, err)` will return a signed JSON Web Token containing a
signed verifiable credential.

```
import (
    "github.com/tbd54566975/web5-go/credentials/vc"
	vcdm "github.com/tbd54566975/web5-go/credentials/vcdatamodel"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/jwt"
)

func main() {
	types := []string{"VerifiableCredential", "UniversityDegreeCredential"}
	issuer := "https://example.edu"
	subjectID := "did:example:ebfeb1f712ebc6f1c276e12ec21"
	issuanceDate := "2010-01-01T19:23:24Z"
	expirationDate := "2039-12-31T19:23:24Z"

	o := vc.CreateCredentialOptions{
		Type:           types,
		Issuer:         issuer,
		Subject:        []vcdm.CredentialSubject{vcdm.IDString(subjectID)},
		IssuanceDate:   issuanceDate,
		ExpirationDate: expirationDate,
	}

	var newVC vc.VerifiableCredential
	err := newVC.Create(o)

	// creating a generic did in order to sign the VC
	bearerDID, didErr := didjwk.Create()

	// sign the VC. You can additionally pass a slice of SignOpts from the jwt package
	signed, signErr := newVC.Sign(&vc.SignVCOptions{
		DID:      bearerDID,
		SignOpts: []jwt.SignOpt{},
	})
}
```
## Verifying

`Verify(jwtStr string) (*jwt.Claims, error)`, given a JWT for a signed Verfiable Credential, will returned a pointer to decoded `jwt.Claims`.

```
import (
	"github.com/tbd54566975/web5-go/credentials/vc"
)

func main() {
	signed := "some signed JWT token which represents a VC"
  
	var newVc vc.VerifiableCredential
	claims, verifyErr := newVc.Verify(signed)
  
	// contains the VerifiableCredential representation that was stored inside the JWT
	verifiableCredential, ok := claims.Misc["vc"]
}
```
> [!NOTE]
> Because `jwt.Claims` is generic, it doesn't know anything about your `VerifiableCredential` out of the box. 
> Because of this you must access the `VerifiableCredential` from the `Misc` field `claims.Misc["vc"]`


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

### Rationale

The primary goals of the `credentials` api are:
- To contain the data models correlated to Verifiable Credentials, Presentations, and Presentation Exchanges via the `vcdatamodel` package
- To expose the main functionality of VCs (Create, Sign, Verify) and Presentations