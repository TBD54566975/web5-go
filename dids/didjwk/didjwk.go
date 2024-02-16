package didjwk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/jwk"
)

// createOptions is a struct that contains all options that can be passed to [Create]
type createOptions struct {
	keyManager  crypto.KeyManager
	algorithmID string
}

type CreateOption func(o *createOptions)

// KeyManager is an option that can be passed to Create to provide a KeyManager
func KeyManager(k crypto.KeyManager) CreateOption {
	return func(o *createOptions) {
		o.keyManager = k
	}
}

// AlgorithmID is an option that can be passed to Create to specify a specific
// cryptographic algorithm to use to generate the private key
func AlgorithmID(id string) CreateOption {
	return func(o *createOptions) {
		o.algorithmID = id
	}
}

// Create can be used to create a new `did:jwk`. `did:jwk` is useful in scenarios where:
//   - Offline resolution is preferred
//   - Key rotation is not required
//   - Service endpoints are not necessary
//
// Spec: https://github.com/quartzjer/did-jwk/blob/main/spec.md
func Create(opts ...CreateOption) (did.BearerDID, error) {
	o := createOptions{
		keyManager:  crypto.NewLocalKeyManager(),
		algorithmID: dsa.AlgorithmIDED25519,
	}

	for _, opt := range opts {
		opt(&o)
	}

	keyMgr := o.keyManager

	keyID, err := keyMgr.GeneratePrivateKey(o.algorithmID)
	if err != nil {
		return did.BearerDID{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicJWK, _ := keyMgr.GetPublicKey(keyID)
	bytes, err := json.Marshal(publicJWK)
	if err != nil {
		return did.BearerDID{}, fmt.Errorf("failed to marshal public key: %w", err)
	}

	id := base64.RawURLEncoding.EncodeToString(bytes)

	didJWK := did.DID{
		Method: "jwk",
		URI:    "did:jwk:" + id,
		ID:     id,
	}

	bearerDID := did.BearerDID{
		DID:        didJWK,
		KeyManager: keyMgr,
		Document:   createDocument(didJWK, publicJWK),
	}

	return bearerDID, nil
}

type Resolver struct{}

func (r Resolver) ResolveWithContext(ctx context.Context, uri string) (didcore.ResolutionResult, error) {
	return r.Resolve(uri)
}

// Resolve the provided DID URI (must be a did:jwk) as per the wee bit of detail provided in the
// spec: https://github.com/quartzjer/did-jwk/blob/main/spec.md
func (r Resolver) Resolve(uri string) (didcore.ResolutionResult, error) {
	did, err := did.Parse(uri)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	if did.Method != "jwk" {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	decodedID, err := base64.RawURLEncoding.DecodeString(did.ID)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	var jwk jwk.JWK
	err = json.Unmarshal(decodedID, &jwk)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	doc := createDocument(did, jwk)
	return didcore.ResolutionResultWithDocument(doc), nil
}

func createDocument(did did.DID, publicKey jwk.JWK) didcore.Document {
	doc := didcore.Document{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      did.URI,
	}

	vm := didcore.VerificationMethod{
		ID:           did.URI + "#0",
		Type:         "JsonWebKey2020",
		Controller:   did.URI,
		PublicKeyJwk: &publicKey,
	}

	doc.AddVerificationMethod(
		vm,
		didcore.Purposes("assertionMethod", "authentication", "capabilityInvocation", "capabilityDelegation"),
	)

	return doc
}
