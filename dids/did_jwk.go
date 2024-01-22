package dids

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/common"
	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/jwk"
)

type options struct {
	keyManager  crypto.KeyManager
	algorithmID string
}

type Option func(o *options)

func KeyManager(k crypto.KeyManager) Option {
	return func(o *options) {
		o.keyManager = k
	}
}

func AlgorithmID(id string) Option {
	return func(o *options) {
		o.algorithmID = id
	}
}

type DIDJWK struct {
	DID
}

func NewDIDJWK(opts ...Option) (DIDJWK, error) {
	o := &options{
		keyManager:  crypto.NewInMemoryKeyManager(),
		algorithmID: dsa.AlgorithmID.ED25519,
	}

	for _, opt := range opts {
		opt(o)
	}

	keyMgr := o.keyManager

	keyID, err := keyMgr.GeneratePrivateKey(o.algorithmID)
	if err != nil {
		return DIDJWK{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicJWK, _ := keyMgr.GetPublicKey(keyID)
	bytes, err := json.Marshal(publicJWK)
	if err != nil {
		return DIDJWK{}, fmt.Errorf("failed to marshal public key: %w", err)
	}

	id := common.Base64UrlEncodeNoPadding(bytes)
	did := DID{
		DIDURI: DIDURI{
			Method: "jwk",
			URI:    "did:jwk:" + id,
			ID:     id,
		},
		KeyManager: keyMgr,
	}

	return DIDJWK{did}, nil
}

func ResolveDIDJWK(uri string) ResolutionResult {
	didURI, err := ParseURI(uri)
	if err != nil {
		return ResolutionResultWithError("invalidDid")
	}

	if didURI.Method != "jwk" {
		return ResolutionResultWithError("invalidDid")
	}

	decodedID, err := common.Base64UrlDecodeNoPadding(didURI.ID)
	if err != nil {
		return ResolutionResultWithError("invalidDid")
	}

	var jwk jwk.JWK
	err = json.Unmarshal(decodedID, &jwk)
	if err != nil {
		return ResolutionResultWithError("invalidDid")
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

	return ResolutionResultWithDocument(doc)
}
