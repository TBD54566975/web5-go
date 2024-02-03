# `jwt` <!-- omit in toc -->

# Table of Contents

- [Table of Contents](#table-of-contents)
- [Usage](#usage)
  - [Signing](#signing)
  - [Verifying](#verifying)
- [Directory Structure](#directory-structure)
    - [Rationale](#rationale)


# Usage 

## Signing

```go
package main

import (
	"fmt"
	"github.com/tbd54566975/web5-go/didjwk"
    "github.com/tbd54566975/web5-go/jwt"
)

func main() {	
	did, err := didjwk.Create()
	if err != nil {
		panic(err)
	}

	claims := jwt.Claims{
		Issuer: did.URI,
		Misc:   map[string]interface{}{"c_nonce": "abcd123"},
	}

	jwt, err := jwt.Sign(claims, did)
	if err != nil {
		panic(err)
	}
}
```


## Verifying
```go
package main

import (
	"fmt"
	"github.com/tbd54566975/web5-go/dids"
    "github.com/tbd54566975/web5-go/jwt"
)

func main() {
    someJWT := "SOME_JWT"
	ok, err := jwt.Verify(signedJWT)
	if err != nil {
		panic(err)
	}

    if (!ok) {
        fmt.Printf("dookie JWT")
    }
}
```

specifying a specific category of key to use relative to the did provided can be done in the same way shown with `jws.Sign`

# Directory Structure

```
jwt
├── jwt.go
└── jwt_test.go
```

### Rationale 
same as `jws`. 