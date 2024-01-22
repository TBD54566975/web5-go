package jws

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tbd54566975/web5-go/common"
	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/dids"
)

var didResolver = dids.GetDefaultResolver()

// Header represents a JWS (JSON Web Signature) header. See [Specification] for more details.
// [Specification]: https://datatracker.ietf.org/doc/html/rfc7515#section-4
type Header struct {
	// Ide	ntifies the cryptographic algorithm used to secure the JWS. The JWS Signature value is not
	// valid if the "alg" value does not represent a supported algorithm or if there is not a key for
	// use with that algorithm associated with the party that digitally signed or MACed the content.
	//
	// "alg" values should either be registered in the IANA "JSON Web Signature and Encryption
	// Algorithms" registry or be a value that contains a Collision-Resistant Name. The "alg" value is
	// a case-sensitive ASCII string.  This Header Parameter MUST be present and MUST be understood
	// and processed by implementations.
	//
	// [Specification]: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1
	ALG string `json:"alg,omitempty"`
	// Key ID Header Parameter
	KID string `json:"kid,omitempty"`
}

type JWSPayload map[string]interface{}

// Base64UrlEncode returns the base64url encoded header.
func (j Header) Base64UrlEncode() string {
	jsonHeader := map[string]string{"alg": j.ALG, "kid": j.KID}
	bytes, _ := json.Marshal(jsonHeader)

	return common.Base64UrlEncodeNoPadding(bytes)
}

// DecodeJWSHeader decodes the base64url encoded JWS header.
func DecodeJWSHeader(base64UrlEncodedHeader string) (Header, error) {
	bytes, err := common.Base64UrlDecodeNoPadding(base64UrlEncodedHeader)
	if err != nil {
		return Header{}, err
	}

	var header Header
	err = json.Unmarshal(bytes, &header)
	if err != nil {
		return Header{}, err
	}

	return header, nil
}

// options that sign function can take
type signOpts struct {
	purpose  string
	detached bool
}

// SignOpts is a type that represents an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
type SignOpts func(opts *signOpts)

// Purpose is an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
// It is used to select the appropriate key to sign with
func Purpose(purpose string) SignOpts {
	return func(opts *signOpts) {
		opts.purpose = purpose
	}
}

// DetatchedPayload is an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
// It is used to indicate whether the payload should be included in the signature.
// More details can be found in [Specification].
// [Specification]: https://datatracker.ietf.org/doc/html/rfc7515#appendix-F
func DetatchedPayload(detached bool) SignOpts {
	return func(opts *signOpts) {
		opts.detached = detached
	}
}

// Sign signs the provided payload with a key associated to the provided DID.
// if no purpose is provided, the default is "assertionMethod". Passing Detached(true)
// will return a compact JWS with detached content
func Sign(payload JWSPayload, did dids.DID, opts ...SignOpts) (string, error) {
	o := signOpts{purpose: "assertionMethod", detached: false}
	for _, opt := range opts {
		opt(&o)
	}

	resolutionResult := dids.GetDefaultResolver().Resolve(did.URI)
	if resolutionResult.GetError() != "" {
		return "", fmt.Errorf("DID resolution error: %s", resolutionResult.GetError())
	}

	var verificationMethodID string
	switch o.purpose {
	case "assertionMethod":
		verificationMethodID = resolutionResult.Document.AssertionMethod[0]
	case "authentication":
		verificationMethodID = resolutionResult.Document.Authentication[0]
	default:
		return "", fmt.Errorf("unsupported purpose: %s", o.purpose)
	}

	if verificationMethodID == "" {
		return "", fmt.Errorf("no verification method found for purpose: %s", o.purpose)
	}

	var verificationMethod dids.VerificationMethod
	for _, vm := range resolutionResult.Document.VerificationMethod {
		if vm.ID == verificationMethodID {
			verificationMethod = vm
			break
		}
	}

	if verificationMethod == (dids.VerificationMethod{}) {
		return "", fmt.Errorf("no verification method found for purpose: %s", o.purpose)
	}

	keyAlias, err := verificationMethod.PublicKeyJwk.ComputeThumbprint()
	if err != nil {
		return "", fmt.Errorf("failed to compute key alias: %s", err.Error())
	}

	if verificationMethod.ID[0] == '#' {
		verificationMethodID = did.URI + verificationMethod.ID
	} else {
		verificationMethodID = verificationMethod.ID
	}

	jwa, err := dsa.GetJWA(verificationMethod.PublicKeyJwk)
	if err != nil {
		return "", fmt.Errorf("failed to determine alg: %s", err.Error())
	}

	header := Header{ALG: jwa, KID: verificationMethodID}
	base64UrlEncodedHeader := header.Base64UrlEncode()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %s", err.Error())
	}

	base64UrlEncodedPayload := common.Base64UrlEncodeNoPadding(payloadBytes)

	toSign := base64UrlEncodedHeader + "." + base64UrlEncodedPayload
	toSignBytes := []byte(toSign)

	signature, err := did.Sign(keyAlias, toSignBytes)
	if err != nil {
		return "", fmt.Errorf("failed to compute signature: %s", err.Error())
	}

	base64UrlEncodedSignature := common.Base64UrlEncodeNoPadding(signature)

	var compactJWS string
	if o.detached {
		compactJWS = base64UrlEncodedHeader + "." + base64UrlEncodedSignature
	} else {
		compactJWS = toSign + "." + base64UrlEncodedSignature
	}

	return compactJWS, nil
}

func Verify(compactJWS string) (bool, error) {
	parts := strings.Split(compactJWS, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("malformed JWS. Expected 3 parts, got %d", len(parts))
	}

	base64UrlEncodedHeader := parts[0]
	header, err := DecodeJWSHeader(base64UrlEncodedHeader)
	if err != nil {
		return false, fmt.Errorf("malformed JWS. Failed to decode header: %s", err.Error())
	}

	if header.ALG == "" || header.KID == "" {
		return false, fmt.Errorf("malformed JWS header. alg and kid are required")
	}

	verificationMethodID := header.KID
	verificationMethodIDParts := strings.Split(verificationMethodID, "#")
	if len(verificationMethodIDParts) != 2 {
		return false, fmt.Errorf("malformed JWS header. kid must be a DID URL")
	}

	base64UrlEncodedPayload := parts[1]
	payloadBytes, err := common.Base64UrlDecodeNoPadding(base64UrlEncodedPayload)
	if err != nil {
		return false, fmt.Errorf("malformed JWS. Failed to decode payload: %s", err.Error())
	}

	var payload JWSPayload
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return false, fmt.Errorf("malformed JWS. Failed to unmarshal payload: %s", err.Error())
	}

	base64UrlEncodedSignature := parts[2]
	signature, err := common.Base64UrlDecodeNoPadding(base64UrlEncodedSignature)
	if err != nil {
		return false, fmt.Errorf("malformed JWS. Failed to decode signature: %s", err.Error())
	}

	toVerify := base64UrlEncodedHeader + "." + base64UrlEncodedPayload
	toVerifyBytes := []byte(toVerify)

	var didURI = verificationMethodIDParts[0]

	resolutionResult := didResolver.Resolve(didURI)
	if resolutionResult.GetError() != "" {
		return false, fmt.Errorf("failed to resolve DID. error: %s", resolutionResult.GetError())
	}

	var verificationMethod dids.VerificationMethod
	for _, vm := range resolutionResult.Document.VerificationMethod {
		if vm.ID == verificationMethodID {
			verificationMethod = vm
			break
		}
	}

	if verificationMethod == (dids.VerificationMethod{}) {
		return false, fmt.Errorf("no verification method found that matches kid: %s", verificationMethodID)
	}

	verified, err := dsa.Verify(toVerifyBytes, signature, verificationMethod.PublicKeyJwk)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %s", err.Error())
	}

	return verified, nil
}
