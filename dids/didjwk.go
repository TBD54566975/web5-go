package dids

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/jwk"
)

type newDIDJWKOptions struct {
	keyManager  crypto.KeyManager
	algorithmID string
}

type NewDIDJWKOption func(o *newDIDJWKOptions)

// KeyManager is an option that can be passed to NewDIDJWK to provide a KeyManager
func KeyManager(k crypto.KeyManager) NewDIDJWKOption {
	return func(o *newDIDJWKOptions) {
		o.keyManager = k
	}
}

// AlgorithmID is an option that can be passed to NewDIDJWK to specify a specific
// cryptographic algorithm to use to generate the private key
func AlgorithmID(id string) NewDIDJWKOption {
	return func(o *newDIDJWKOptions) {
		o.algorithmID = id
	}
}

// NewDIDJWK can be used to generate a new `did:jwk`. `did:jwk` is useful in scenarios where:
//   - Offline resolution is preferred
//   - Key rotation is not required
//   - Service endpoints are not necessary
//
// Spec: https://github.com/quartzjer/did-jwk/blob/main/spec.md
func NewDIDJWK(opts ...NewDIDJWKOption) (BearerDID, error) {
	o := newDIDJWKOptions{
		keyManager:  crypto.NewLocalKeyManager(),
		algorithmID: dsa.AlgorithmIDED25519,
	}

	for _, opt := range opts {
		opt(&o)
	}

	keyMgr := o.keyManager

	keyID, err := keyMgr.GeneratePrivateKey(o.algorithmID)
	if err != nil {
		return BearerDID{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicJWK, _ := keyMgr.GetPublicKey(keyID)
	bytes, err := json.Marshal(publicJWK)
	if err != nil {
		return BearerDID{}, fmt.Errorf("failed to marshal public key: %w", err)
	}

	id := base64.RawURLEncoding.EncodeToString(bytes)
	did := BearerDID{
		DID: DID{
			Method: "jwk",
			URI:    "did:jwk:" + id,
			ID:     id,
		},
		KeyManager: keyMgr,
	}

	return did, nil
}

// Resolves the provided DID URI
func ResolveDIDJWK(uri string) (ResolutionResult, error) {
	did, err := Parse(uri)
	if err != nil {
		return ResolutionResultWithError("invalidDid"), ResolutionError{"invalidDid"}
	}

	if did.Method != "jwk" {
		return ResolutionResultWithError("invalidDid"), ResolutionError{"invalidDid"}
	}

	decodedID, err := base64.RawURLEncoding.DecodeString(did.ID)
	if err != nil {
		return ResolutionResultWithError("invalidDid"), ResolutionError{"invalidDid"}
	}

	var jwk jwk.JWK
	err = json.Unmarshal(decodedID, &jwk)
	if err != nil {
		return ResolutionResultWithError("invalidDid"), ResolutionError{"invalidDid"}
	}

	doc := Document{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      uri,
	}

	vm := VerificationMethod{
		ID:           uri + "#0",
		Type:         "JsonWebKey2020",
		Controller:   uri,
		PublicKeyJwk: jwk,
	}

	doc.AddVerificationMethod(
		vm,
		Purposes("assertionMethod", "authentication", "capabilityInvocation", "capabilityDelegation"),
	)

	return ResolutionResultWithDocument(doc), nil
}
