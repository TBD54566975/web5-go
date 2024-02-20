package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/jws"
)

// Decode decodes the 3-part base64url encoded jwt into it's relevant parts
func Decode(jwt string) (Decoded, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return Decoded{}, fmt.Errorf("malformed JWT. Expected 3 parts, got %d", len(parts))
	}

	header, err := jws.DecodeHeader(parts[0])
	if err != nil {
		return Decoded{}, err
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWT. Failed to decode claims: %w", err)
	}

	claims := Claims{}
	err = json.Unmarshal(claimsBytes, &claims)
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWT. Failed to unmarshal claims: %w", err)
	}

	signature, err := jws.DecodeSignature(parts[2])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWT. Failed to decode signature: %w", err)
	}

	return Decoded{
		Header:    header,
		Claims:    claims,
		Signature: signature,
		Parts:     parts,
	}, nil
}

// signOpts is a type that holds all the options that can be passed to Sign
type signOpts struct{ selector didcore.VMSelector }

// SignOpt is a type returned by all individual Sign Options.
type SignOpt func(opts *signOpts)

// Purpose is an option that can be provided to Sign to specify that a key from
// a given DID Document Verification Relationship should be used (e.g. authentication)
// Purpose is an option that can be passed to [github.com/tbd54566975/web5-go/jws.Sign].
// It is used to select the appropriate key to sign with
func Purpose(p string) SignOpt {
	return func(opts *signOpts) {
		opts.selector = didcore.Purpose(p)
	}
}

// Sign signs the provided JWT Claims with the provided BearerDID.
// The Purpose option can be provided to specify that a key from a given
// DID Document Verification Relationship should be used (e.g. authentication).
// defaults to using assertionMethod
func Sign(claims Claims, did did.BearerDID, opts ...SignOpt) (string, error) {
	o := signOpts{selector: nil}
	for _, opt := range opts {
		opt(&o)
	}

	return jws.Sign(claims, did, jws.VMSelector(o.selector))
}

// Verify verifies a JWT (JSON Web Token) as per the spec https://datatracker.ietf.org/doc/html/rfc7519
// Successful verification means that the JWT has not expired and the signature's integrity is intact
// Decoded JWT is returned if verification is successful
func Verify(jwt string) (Decoded, error) {
	decodedJWT, err := Decode(jwt)
	if err != nil {
		return Decoded{}, err
	}

	err = decodedJWT.Verify()

	return decodedJWT, err
}

// Header are JWS Headers. type aliasing because this could cause confusion
// for non-neckbeards
type Header = jws.Header

// Decoded represents a JWT Decoded into it's relevant parts
type Decoded struct {
	Header    Header
	Claims    Claims
	Signature []byte
	Parts     []string
}

// Verify verifies a JWT (JSON Web Token)
func (jwt Decoded) Verify() error {
	if jwt.Claims.Expiration != 0 && time.Now().Unix() > jwt.Claims.Expiration {
		return errors.New("JWT has expired")
	}

	decodedJWS := jws.Decoded{
		Header:    jwt.Header,
		Payload:   jwt.Claims,
		Signature: jwt.Signature,
		Parts:     jwt.Parts,
	}

	err := decodedJWS.Verify()
	if err != nil {
		return fmt.Errorf("JWT signature verification failed: %w", err)
	}

	return nil
}

// Claims represents JWT (JSON Web Token) Claims
//
// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4
type Claims struct {
	// The "iss" (issuer) claim identifies the principal that issued the
	// JWT.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`
	// The "sub" (subject) claim identifies the principal that is the
	// subject of the JWT.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// The "aud" (audience) claim identifies the recipients that the JWT is
	// intended for.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience string `json:"aud,omitempty"`

	// The "exp" (expiration time) claim identifies the expiration time on
	// or after which the JWT must not be accepted for processing.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	Expiration int64 `json:"exp,omitempty"`

	// The "nbf" (not before) claim identifies the time before which the JWT
	// must not be accepted for processing.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore int64 `json:"nbf,omitempty"`

	// The "iat" (issued at) claim identifies the time at which the JWT was
	// issued.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt int64 `json:"iat,omitempty"`

	// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	JTI string `json:"jti,omitempty"`

	Misc map[string]any `json:"-"`
}

// MarshalJSON overrides default json.Marshal behavior to include misc claims as flattened
// properties of the top-level object
func (c Claims) MarshalJSON() ([]byte, error) {
	copied := cpy(c)

	bytes, err := json.Marshal(copied)
	if err != nil {
		return nil, err
	}

	var combined map[string]interface{}
	err = json.Unmarshal(bytes, &combined)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal jwt claims: %w", err)
	}

	// Add private claims to the map
	for key, value := range c.Misc {
		combined[key] = value
	}

	return json.Marshal(combined)
}

// UnmarshalJSON overrides default json.Unmarshal behavior to place flattened Misc
// claims into Misc
func (c *Claims) UnmarshalJSON(b []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	registeredClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true,
		"exp": true, "nbf": true, "iat": true,
		"jti": true,
	}

	misc := make(map[string]any)
	for key, value := range m {
		if _, ok := registeredClaims[key]; !ok {
			misc[key] = value
		}
	}

	claims := cpy{}
	if err := json.Unmarshal(b, &claims); err != nil {
		return err
	}

	claims.Misc = misc
	*c = Claims(claims)

	return nil
}

// cpy is a copy of Claims that is used to marshal/unmarshal the claims without infinitely looping
type cpy Claims
