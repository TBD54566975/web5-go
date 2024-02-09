package jws

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/dids"
	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
)

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
	// Key ID Header Parameter https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
	KID string `json:"kid,omitempty"`
	// Type Header Parameter https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9
	Type string `json:"typ,omitempty"`
}

type JWSPayload any

// Base64UrlEncode returns the base64url encoded header.
func (j Header) Base64UrlEncode() string {
	jsonHeader := map[string]string{"alg": j.ALG, "kid": j.KID}
	bytes, _ := json.Marshal(jsonHeader)

	return base64.RawURLEncoding.EncodeToString(bytes)
}

// DecodeHeader decodes the base64url encoded JWS header.
func DecodeHeader(base64UrlEncodedHeader string) (Header, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(base64UrlEncodedHeader)
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
	selector didcore.VMSelector
	detached bool
}

// SignOpts is a type that represents an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
type SignOpts func(opts *signOpts)

// Purpose is an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
// It is used to select the appropriate key to sign with
func Purpose(p string) SignOpts {
	return func(opts *signOpts) {
		opts.selector = didcore.Purpose(p)
	}
}

func VerificationMethod(id string) SignOpts {
	return func(opts *signOpts) {
		opts.selector = didcore.ID(id)
	}
}

func VMSelector(selector didcore.VMSelector) SignOpts {
	return func(opts *signOpts) {
		opts.selector = selector
	}
}

// DetachedPayload is an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
// It is used to indicate whether the payload should be included in the signature.
// More details can be found in [Specification].
// [Specification]: https://datatracker.ietf.org/doc/html/rfc7515#appendix-F
func DetachedPayload(detached bool) SignOpts {
	return func(opts *signOpts) {
		opts.detached = detached
	}
}

// Sign signs the provided payload with a key associated to the provided DID.
// if no purpose is provided, the default is "assertionMethod". Passing Detached(true)
// will return a compact JWS with detached content
func Sign(payload JWSPayload, did did.BearerDID, opts ...SignOpts) (string, error) {
	o := signOpts{selector: nil, detached: false}
	for _, opt := range opts {
		opt(&o)
	}

	sign, verificationMethod, err := did.GetSigner(o.selector)
	if err != nil {
		return "", fmt.Errorf("failed to get signer: %s", err.Error())
	}

	jwa, err := dsa.GetJWA(*verificationMethod.PublicKeyJwk)
	if err != nil {
		return "", fmt.Errorf("failed to determine alg: %s", err.Error())
	}

	// TODO: consider putting this logic into did.getSigner and returning just the verification method id instead of the
	//       entire verification method. this is very esoteric did spec detail
	var keyID string
	if verificationMethod.ID[0] == '#' {
		keyID = did.URI + verificationMethod.ID
	} else {
		keyID = verificationMethod.ID
	}

	header := Header{ALG: jwa, KID: keyID}
	base64UrlEncodedHeader := header.Base64UrlEncode()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %s", err.Error())
	}

	base64UrlEncodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	toSign := base64UrlEncodedHeader + "." + base64UrlEncodedPayload
	toSignBytes := []byte(toSign)

	signature, err := sign(toSignBytes)
	if err != nil {
		return "", fmt.Errorf("failed to compute signature: %s", err.Error())
	}

	base64UrlEncodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	var compactJWS string
	if o.detached {
		compactJWS = base64UrlEncodedHeader + "." + "." + base64UrlEncodedSignature
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
	header, err := DecodeHeader(base64UrlEncodedHeader)
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
	payloadBytes, err := base64.RawURLEncoding.DecodeString(base64UrlEncodedPayload)
	if err != nil {
		return false, fmt.Errorf("malformed JWS. Failed to decode payload: %s", err.Error())
	}

	var payload JWSPayload
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return false, fmt.Errorf("malformed JWS. Failed to unmarshal payload: %s", err.Error())
	}

	base64UrlEncodedSignature := parts[2]
	signature, err := base64.RawURLEncoding.DecodeString(base64UrlEncodedSignature)
	if err != nil {
		return false, fmt.Errorf("malformed JWS. Failed to decode signature: %s", err.Error())
	}

	toVerify := base64UrlEncodedHeader + "." + base64UrlEncodedPayload
	toVerifyBytes := []byte(toVerify)

	var didURI = verificationMethodIDParts[0]

	resolutionResult, err := dids.Resolve(didURI)
	if err != nil {
		return false, fmt.Errorf("failed to resolve DID: %w", err)
	}

	var verificationMethod didcore.VerificationMethod
	for _, vm := range resolutionResult.Document.VerificationMethod {
		if vm.ID == verificationMethodID {
			verificationMethod = vm
			break
		}
	}

	if verificationMethod == (didcore.VerificationMethod{}) {
		return false, fmt.Errorf("no verification method found that matches kid: %s", verificationMethodID)
	}

	verified, err := dsa.Verify(toVerifyBytes, signature, *verificationMethod.PublicKeyJwk)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %s", err.Error())
	}

	return verified, nil
}
