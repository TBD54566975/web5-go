package dids

import (
	"fmt"

	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/jwk"
)

// BearerDID is a composite type that combines a DID with a KeyManager containing keys
// associated to the DID. Together, these two components form a BearerDID that can be used to
// sign and verify data.
type BearerDID struct {
	DID
	crypto.KeyManager
}

// ToKeys exports a BearerDID into a portable format that contains the DID's URI in addition to
// every private key associated with a verification method.
func (d *BearerDID) ToKeys() (PortableDID, error) {
	exporter, ok := d.KeyManager.(crypto.KeyExporter)
	if !ok {
		return PortableDID{}, fmt.Errorf("key manager does not implement KeyExporter")
	}

	resolutionResult, err := Resolve(d.URI)
	if err != nil {
		return PortableDID{}, fmt.Errorf("failed to resolve DID: %w", err)
	}

	portableDID := PortableDID{URI: d.URI}
	keys := make([]VerificationMethodKeyPair, 0)

	didDoc := resolutionResult.Document
	for _, vm := range didDoc.VerificationMethod {
		keyAlias, err := vm.PublicKeyJwk.ComputeThumbprint()
		if err != nil {
			continue
		}

		key, err := exporter.ExportKey(keyAlias)
		if err != nil {
			continue
		}

		keys = append(keys, VerificationMethodKeyPair{
			PublicKeyJWK:  vm.PublicKeyJwk,
			PrivateKeyJWK: key,
		})
	}

	portableDID.VerificationMethod = keys

	return portableDID, nil
}

// FromKeys imports a BearerDID from a portable format that contains the DID's URI in addition to
// every private key associated with a verification method.
func BearerDIDFromKeys(portableDID PortableDID) (BearerDID, error) {
	didURI, err := Parse(portableDID.URI)
	if err != nil {
		return BearerDID{}, err
	}

	keyManager := crypto.NewLocalKeyManager()
	for _, vm := range portableDID.VerificationMethod {
		keyManager.ImportKey(vm.PrivateKeyJWK)
	}

	return BearerDID{
		DID:        didURI,
		KeyManager: keyManager,
	}, nil
}

// PortableDID is a serializable BearerDID. VerificationMethod contains the private key
// of each verification method that the BearerDID's key manager contains
type PortableDID struct {
	URI                string                      `json:"uri"`
	VerificationMethod []VerificationMethodKeyPair `json:"verificationMethod"`
}

// VerificationMethodKeyPair is a public/private keypair associated to a
// BearerDID's verification method. Used in PortableDID
type VerificationMethodKeyPair struct {
	PublicKeyJWK  jwk.JWK `json:"publicKeyJwk"`
	PrivateKeyJWK jwk.JWK `json:"privateKeyJwk"`
}
