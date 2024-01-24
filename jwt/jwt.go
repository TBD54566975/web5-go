package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tbd54566975/web5-go/common"
	"github.com/tbd54566975/web5-go/dids"
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

// cpy is a copy of Claims that is used to marshal/unmarshal the claims without infinitely looping
type cpy Claims

func (c Claims) Base64UrlEncode() string {
	bytes, err := json.Marshal(c)
	if err != nil {
		fmt.Errorf("error marshaling claims: %v", err)
	}

	return common.Base64UrlEncodeNoPadding(bytes)
}

func (c Claims) MarshalJSON() ([]byte, error) {
	copied := cpy(c)

	bytes, err := json.Marshal(copied)
	if err != nil {
		return nil, err
	}

	var combined map[string]interface{}
	json.Unmarshal(bytes, &combined)

	// Add private claims to the map
	for key, value := range c.Misc {
		combined[key] = value
	}

	return json.Marshal(combined)
}

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

type signOpts struct{ purpose string }

type SignOpt func(opts *signOpts)

func Sign(claims Claims, did dids.BearerDID, opts ...SignOpt) (string, error) {
	o := signOpts{purpose: "assertionMethod"}
	for _, opt := range opts {
		opt(&o)
	}

	return jws.Sign(claims, did, jws.Purpose(o.purpose))
}

func Verify(jwt string) (bool, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("malformed JWT. Expected 3 parts, got %d", len(parts))
	}

	b64urlClaims := parts[1]
	claimsBytes, err := common.Base64UrlDecodeNoPadding(b64urlClaims)
	if err != nil {
		return false, fmt.Errorf("malformed JWT claims. %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return false, fmt.Errorf("malformed JWT claims. %w", err)
	}

	if claims.Expiration != 0 && time.Now().Unix() > int64(claims.Expiration) {
		return false, fmt.Errorf("JWT has expired")
	}

	return jws.Verify(jwt)
}
