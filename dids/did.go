package dids

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/jwk"
)

// DID provides a way to parse and handle Decentralized Identifier (DID) URIs
// according to the W3C DID Core specification (https://www.w3.org/TR/did-core/).
type DID struct {
	// URI represents the complete Decentralized Identifier (DID) URI.
	// Spec: https://www.w3.org/TR/did-core/#did-syntax
	URI string

	// Method specifies the DID method in the URI, which indicates the underlying
	// method-specific identifier scheme (e.g., jwk, dht, key, etc.).
	// Spec: https://www.w3.org/TR/did-core/#method-schemes
	Method string

	// ID is the method-specific identifier in the DID URI.
	// Spec: https://www.w3.org/TR/did-core/#method-specific-id
	ID string

	// Params is a map containing optional parameters present in the DID URI.
	// These parameters are method-specific.
	// Spec: https://www.w3.org/TR/did-core/#did-parameters
	Params map[string]string

	// Path is an optional path component in the DID URI.
	// Spec: https://www.w3.org/TR/did-core/#path
	Path string

	// Query is an optional query component in the DID URI, used to express a request
	// for a specific representation or resource related to the DID.
	// Spec: https://www.w3.org/TR/did-core/#query
	Query string

	// Fragment is an optional fragment component in the DID URI, used to reference
	// a specific part of a DID document.
	// Spec: https://www.w3.org/TR/did-core/#fragment
	Fragment string
}

var (
	pctEncodedPattern = `(?:%[0-9a-fA-F]{2})`
	idCharPattern     = `(?:[a-zA-Z0-9._-]|` + pctEncodedPattern + `)`
	methodPattern     = `([a-z0-9]+)`
	methodIDPattern   = `((?:` + idCharPattern + `*:)*(` + idCharPattern + `+))`
	paramCharPattern  = `[a-zA-Z0-9_.:%-]`
	paramPattern      = `;` + paramCharPattern + `+=` + paramCharPattern + `*`
	paramsPattern     = `((` + paramPattern + `)*)`
	pathPattern       = `(/[^#?]*)?`
	queryPattern      = `(\?[^\#]*)?`
	fragmentPattern   = `(\#.*)?`
	didURIPattern     = regexp.MustCompile(`^did:` + methodPattern + `:` + methodIDPattern + paramsPattern + pathPattern + queryPattern + fragmentPattern + `$`)
)

// ParseURI parses a DID URI in accordance to the ABNF rules specified in the
// specification here: https://www.w3.org/TR/did-core/#did-syntax. Returns
// a DIDURI instance if parsing is successful. Otherwise, returns an error.
func ParseURI(input string) (DID, error) {
	match := didURIPattern.FindStringSubmatch(input)

	if match == nil {
		return DID{}, fmt.Errorf("invalid DID URI")
	}

	didURI := DID{
		URI:    "did:" + match[1] + ":" + match[2],
		Method: match[1],
		ID:     match[2],
	}

	if len(match[4]) > 0 {
		params := strings.Split(match[4][1:], ";")
		parsedParams := make(map[string]string)
		for _, p := range params {
			kv := strings.Split(p, "=")
			parsedParams[kv[0]] = kv[1]
		}
		didURI.Params = parsedParams
	}

	if match[6] != "" {
		didURI.Path = match[6]
	}
	if match[7] != "" {
		didURI.Query = match[7][1:]
	}
	if match[8] != "" {
		didURI.Fragment = match[8][1:]
	}

	return didURI, nil
}

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

	resolver := GetDefaultResolver()
	resolutionResult := resolver.Resolve(d.URI)
	if resolutionResult.GetError() != "" {
		return PortableDID{}, fmt.Errorf("failed to resolve DID: %s", resolutionResult.GetError())
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
func FromKeys(portableDID PortableDID) (BearerDID, error) {
	didURI, err := ParseURI(portableDID.URI)
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
