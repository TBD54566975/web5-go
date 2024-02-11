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

func Decode(jws string) (Decoded, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return Decoded{}, fmt.Errorf("malformed JWS. Expected 3 parts, got %d", len(parts))
	}

	header, err := DecodeHeader(parts[0])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWS. Failed to decode header: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWS. Failed to decode payload: %s", err.Error())
	}

	var payload Payload
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWS. Failed to unmarshal payload: %s", err.Error())
	}

	signature, err := DecodeSignature(parts[2])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWS. Failed to decode signature: %s", err.Error())
	}

	return Decoded{
		Header:    header,
		Payload:   payload,
		Signature: signature,
		Parts:     parts,
	}, nil
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

func DecodeSignature(base64UrlEncodedSignature string) ([]byte, error) {
	signature, err := base64.RawURLEncoding.DecodeString(base64UrlEncodedSignature)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// options that sign function can take
type signOpts struct {
	selector didcore.VMSelector
	detached bool
	typ      string
}

// SignOpt is a type that represents an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
type SignOpt func(opts *signOpts)

// Purpose is an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
// It is used to select the appropriate key to sign with
func Purpose(p string) SignOpt {
	return func(opts *signOpts) {
		opts.selector = didcore.Purpose(p)
	}
}

func VerificationMethod(id string) SignOpt {
	return func(opts *signOpts) {
		opts.selector = didcore.ID(id)
	}
}

func VMSelector(selector didcore.VMSelector) SignOpt {
	return func(opts *signOpts) {
		opts.selector = selector
	}
}

// DetachedPayload is an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
// It is used to indicate whether the payload should be included in the signature.
// More details can be found in [Specification].
// [Specification]: https://datatracker.ietf.org/doc/html/rfc7515#appendix-F
func DetachedPayload(detached bool) SignOpt {
	return func(opts *signOpts) {
		opts.detached = detached
	}
}

// Purpose is an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
// It is used to select the appropriate key to sign with
func Type(typ string) SignOpt {
	return func(opts *signOpts) {
		opts.typ = typ
	}
}

// Sign signs the provided payload with a key associated to the provided DID.
// if no purpose is provided, the default is "assertionMethod". Passing Detached(true)
// will return a compact JWS with detached content
func Sign(payload Payload, did did.BearerDID, opts ...SignOpt) (string, error) {
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

	keyID := did.Document.GetAbsoluteResourceID(verificationMethod.ID)
	header := Header{ALG: jwa, KID: keyID, TYP: o.typ}
	base64UrlEncodedHeader, err := header.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to base64 url encode header: %s", err.Error())
	}

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

func Verify(compactJWS string) (Decoded, error) {
	decodedJWS, err := Decode(compactJWS)
	if err != nil {
		return decodedJWS, fmt.Errorf("signature verification failed: %w", err)
	}

	err = decodedJWS.Verify()

	return decodedJWS, err
}

type Decoded struct {
	Header    Header
	Payload   Payload
	Signature []byte
	Parts     []string
}

func (jws Decoded) Verify() error {
	if jws.Header.ALG == "" || jws.Header.KID == "" {
		return fmt.Errorf("malformed JWS header. alg and kid are required")
	}

	verificationMethodID := jws.Header.KID
	verificationMethodIDParts := strings.Split(verificationMethodID, "#")
	if len(verificationMethodIDParts) != 2 {
		return fmt.Errorf("malformed JWS header. kid must be a DID URL")
	}

	var didURI = verificationMethodIDParts[0]

	resolutionResult, err := dids.Resolve(didURI)
	if err != nil {
		return fmt.Errorf("failed to resolve DID: %w", err)
	}

	verificationMethod, err := resolutionResult.Document.SelectVerificationMethod(didcore.ID(verificationMethodID))
	if err != nil {
		return fmt.Errorf("kid does not match any verification method %w", err)
	}

	toVerify := jws.Parts[0] + "." + jws.Parts[1]
	verified, err := dsa.Verify([]byte(toVerify), jws.Signature, *verificationMethod.PublicKeyJwk)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	if !verified {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

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
	TYP string `json:"typ,omitempty"`
}

// Encode returns the base64url encoded header.
func (j Header) Encode() (string, error) {
	bytes, err := json.Marshal(j)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

type Payload any
