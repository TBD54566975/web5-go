package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/jws"
)

// Header are JWS Headers. type aliasing because this could cause confusion
// for non-neckbeards
type Header = jws.Header

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
	Expiration uint64 `json:"exp,omitempty"`

	// The "nbf" (not before) claim identifies the time before which the JWT
	// must not be accepted for processing.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore uint64 `json:"nbf,omitempty"`

	// The "iat" (issued at) claim identifies the time at which the JWT was
	// issued.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt uint64 `json:"iat,omitempty"`

	// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	JTI string `json:"jti,omitempty"`

	Misc map[string]interface{} `json:"-"`
}

type DecodedJWT struct {
	Header    Header
	Claims    Claims
	Signature string
}

// cpy is a copy of Claims that is used to marshal/unmarshal the claims without infinitely looping
type cpy Claims

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

	private := make(map[string]interface{})
	for key, value := range m {
		if _, ok := registeredClaims[key]; !ok {
			private[key] = value
		}
	}

	claims := cpy{}
	if err := json.Unmarshal(b, &claims); err != nil {
		return err
	}

	claims.Misc = private
	*c = Claims(claims)

	return nil
}

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

// Verify verifies a JWT (JSON Web Token)
func Verify(jwt string) (bool, error) {
	decodedJWT, err := Decode(jwt)
	if err != nil {
		return false, err
	}

	return decodedJWT.Verify()
}

// Verify verifies a JWT (JSON Web Token)
func (jwt DecodedJWT) Verify() (bool, error) {
	if jwt.Claims.Expiration != 0 && time.Now().Unix() > int64(jwt.Claims.Expiration) {
		return false, fmt.Errorf("JWT has expired")
	}

	// todo rather than having to encode this here, could we augment the jws.Verify function signatures?
	encodedJWT, err := jwt.Encode()
	if err != nil {
		return false, err
	}

	return jws.Verify(encodedJWT)
}

func (jwt DecodedJWT) Encode() (string, error) {
	base64UrlEncodedHeader, err := jwt.Header.Base64UrlEncode()
	if err != nil {
		return "", err
	}

	base64UrlEncodedClaims, err := jwt.Claims.Base64UrlEncode()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", base64UrlEncodedHeader, base64UrlEncodedClaims, jwt.Signature), nil
}

// Base64UrlEncode returns the base64url encoded header.
func (claims Claims) Base64UrlEncode() (string, error) {
	bytes, err := claims.MarshalJSON()
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// DecodeClaims decodes the base64url encoded JWT claims.
func DecodeClaims(base64UrlEncodedClaims string) (Claims, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(base64UrlEncodedClaims)
	if err != nil {
		return Claims{}, err
	}

	var claims Claims
	err = json.Unmarshal(bytes, &claims)
	if err != nil {
		return Claims{}, err
	}

	return claims, nil
}

// Decode decodes the 3-part base64url encoded jwt into it's relevant parts
func Decode(jwt string) (DecodedJWT, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return DecodedJWT{}, fmt.Errorf("malformed JWT. Expected 3 parts, got %d", len(parts))
	}

	base64UrlEncodedHeader := parts[0]
	base64UrlEncodedClaims := parts[1]
	signature := parts[2]

	header, err := jws.DecodeHeader(base64UrlEncodedHeader)
	if err != nil {
		return DecodedJWT{}, err
	}

	claims, err := DecodeClaims(base64UrlEncodedClaims)
	if err != nil {
		return DecodedJWT{}, err
	}

	return DecodedJWT{Header: header, Claims: claims, Signature: signature}, nil
}
