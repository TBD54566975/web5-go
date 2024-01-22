package dids

import "github.com/tbd54566975/web5-go/jwk"

// VerificationMethod expresses verification methods, such as cryptographic
// public keys, which can be used to authenticate or authorize interactions
// with the DID subject or associated parties. For example,
// a cryptographic public key can be used as a verification method with
// respect to a digital signature; in such usage, it verifies that the
// signer could use the associated cryptographic private key.
//
// Specification Reference: https://www.w3.org/TR/did-core/#verification-methods
type VerificationMethod struct {
	ID string `json:"id"`
	// references exactly one verification method type. In order to maximize global
	// interoperability, the verification method type SHOULD be registered in the
	// DID Specification Registries: https://www.w3.org/TR/did-spec-registries/
	Type string `json:"type"`
	// a value that conforms to the rules in DID Syntax: https://www.w3.org/TR/did-core/#did-syntax
	Controller string `json:"controller"`
	// specification reference: https://www.w3.org/TR/did-core/#dfn-publickeyjwk
	PublicKeyJwk jwk.JWK `json:"publicKeyJwk,omitempty"`
}
