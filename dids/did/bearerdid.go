package did

import (
	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/jwk"
)

// BearerDID is a composite type that combines a DID with a KeyManager containing keys
// associated to the DID. Together, these two components form a BearerDID that can be used to
// sign and verify data.
type BearerDID struct {
	DID
	crypto.KeyManager
	Document didcore.Document
}

// ToPortableDID exports a BearerDID to a portable format
func (d *BearerDID) ToPortableDID() (PortableDID, error) {
	portableDID := PortableDID{
		URI:      d.URI,
		Document: d.Document,
	}

	exporter, ok := d.KeyManager.(crypto.KeyExporter)
	if ok {
		privateKeys := make([]jwk.JWK, 0)

		for _, vm := range d.Document.VerificationMethod {
			keyAlias, err := vm.PublicKeyJwk.ComputeThumbprint()
			if err != nil {
				continue
			}

			key, err := exporter.ExportKey(keyAlias)
			if err != nil {
				// TODO: decide if we want to blow up or continue
				continue
			}

			privateKeys = append(privateKeys, key)
		}

		portableDID.PrivateKeys = privateKeys
	}

	return portableDID, nil
}

// FromPortableDID inflates a BearerDID from a portable format.
func FromPortableDID(portableDID PortableDID) (BearerDID, error) {
	did, err := Parse(portableDID.URI)
	if err != nil {
		return BearerDID{}, err
	}

	keyManager := crypto.NewLocalKeyManager()
	for _, key := range portableDID.PrivateKeys {
		keyManager.ImportKey(key)
	}

	return BearerDID{
		DID:        did,
		KeyManager: keyManager,
		Document:   portableDID.Document,
	}, nil
}
