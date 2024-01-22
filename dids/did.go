package dids

import (
	"github.com/tbd54566975/web5-go/crypto"
)

// DID is a composite type that combines a DID URI with a KeyManager containing keys
// associated to the DID. Together, these two components form a DID that can be used to
// sign and verify data.
type DID struct {
	DIDURI
	crypto.KeyManager
}
