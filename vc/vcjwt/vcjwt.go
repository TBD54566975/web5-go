package vcjwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/jwt"
	"github.com/tbd54566975/web5-go/vc"
)

// SignJWT returns a signed JWT conformant with the [vc-jwt] format.
//
// [vc-jwt]: https://www.w3.org/TR/vc-data-model/#json-web-token
func Sign[T vc.CredentialSubject](vc vc.DataModel[T], bearerDID did.BearerDID, opts ...jwt.SignOpt) (string, error) {
	vc.Issuer = bearerDID.URI
	jwtClaims := jwt.Claims{
		Issuer:  vc.Issuer,
		JTI:     vc.ID,
		Subject: vc.CredentialSubject.GetID(),
	}

	t, err := time.Parse(time.RFC3339, vc.IssuanceDate)
	if err != nil {
		return "", fmt.Errorf("failed to parse issuance date: %w", err)
	}

	jwtClaims.NotBefore = t.Unix()

	if vc.ExpirationDate != "" {
		t, err := time.Parse(time.RFC3339, vc.ExpirationDate)
		if err != nil {
			return "", fmt.Errorf("failed to parse expiration date: %w", err)
		}

		jwtClaims.Expiration = t.Unix()
	}

	jwtClaims.Misc = make(map[string]any)
	jwtClaims.Misc["vc"] = vc

	return jwt.Sign(jwtClaims, bearerDID, opts...)
}

func Verify[T vc.CredentialSubject](vcJWT string) (Decoded[T], error) {
	decoded, err := Decode[T](vcJWT)
	if err != nil {
		return decoded, err
	}

	return decoded, decoded.verify()
}

// Decode decodes a vc-jwt as per the [spec] and returns [Decoded].
// Note: this function uses certain fields from the jwt claims to eagrly populate the vc model as described
// in the encoding section of the spec. The jwt fields will clobber any values that exist in the vc model.
// While the jwt claims should match the counterpart values in the vc model, it's possible that they don't
// but there would be no way to know if they don't match given that they're overwritten.
//
// [spec]: https://www.w3.org/TR/vc-data-model/#json-web-token
func Decode[T vc.CredentialSubject](vcJWT string) (Decoded[T], error) {
	decoded, err := jwt.Decode(vcJWT)
	if err != nil {
		return Decoded[T]{}, fmt.Errorf("failed to decode vc-jwt: %w", err)
	}

	if decoded.Claims.Misc == nil {
		return Decoded[T]{}, fmt.Errorf("vc-jwt missing vc claim")
	}

	if _, ok := decoded.Claims.Misc["vc"]; ok == false {
		return Decoded[T]{}, fmt.Errorf("vc-jwt missing vc claim")
	}

	bytes, err := json.Marshal(decoded.Claims.Misc["vc"])
	if err != nil {
		return Decoded[T]{}, fmt.Errorf("failed to decode vc claim: %w", err)
	}

	var vc vc.DataModel[T]
	if err := json.Unmarshal(bytes, &vc); err != nil {
		return Decoded[T]{}, fmt.Errorf("failed to decode vc claim: %w", err)
	}

	// the following conditionals are included to conform with the jwt decoding section
	// of the specification defined here: https://www.w3.org/TR/vc-data-model/#jwt-decoding
	if decoded.Claims.Issuer != "" {
		vc.Issuer = decoded.Claims.Issuer
	}

	if decoded.Claims.JTI != "" {
		vc.ID = decoded.Claims.JTI
	}

	if decoded.Claims.Subject != "" {
		vc.CredentialSubject.SetID(decoded.Claims.Subject)
	}

	if decoded.Claims.Expiration != 0 {
		vc.ExpirationDate = time.Unix(decoded.Claims.Expiration, 0).UTC().Format(time.RFC3339)
	}

	if decoded.Claims.NotBefore != 0 {
		vc.IssuanceDate = time.Unix(decoded.Claims.NotBefore, 0).UTC().Format(time.RFC3339)
	}

	return Decoded[T]{
		JWT: decoded,
		VC:  vc,
	}, nil

}

type Decoded[T vc.CredentialSubject] struct {
	JWT jwt.Decoded
	VC  vc.DataModel[T]
}

func (vcjwt Decoded[T]) verify() error {
	if vcjwt.VC.Issuer == "" {
		return errors.New("verification failed. missing issuer")
	}

	if vcjwt.VC.ID == "" {
		return errors.New("verification failed. missing id")
	}

	if vcjwt.VC.IssuanceDate == "" {
		return errors.New("verification failed. missing issuance date")
	}

	issuanceDate, err := time.Parse(time.RFC3339, vcjwt.VC.IssuanceDate)
	if err != nil {
		return fmt.Errorf("verification failed. failed to parse issuance date: %w", err)
	}

	if time.Now().UTC().Before(issuanceDate.UTC()) {
		return fmt.Errorf("verification failed. vc cannot be used before %s", vcjwt.VC.IssuanceDate)
	}

	if vcjwt.VC.ExpirationDate != "" {
		exp, err := time.Parse(time.RFC3339, vcjwt.VC.ExpirationDate)
		if err != nil {
			return fmt.Errorf("verification failed. failed to parse expiration date: %w", err)
		}

		if time.Now().UTC().After(exp.UTC()) {
			return fmt.Errorf("verification failed. vc expired on %s", vcjwt.VC.ExpirationDate)
		}
	}

	if vcjwt.VC.Type == nil || len(vcjwt.VC.Type) == 0 {
		return errors.New("verification failed. missing type")
	}

	if slices.Contains(vcjwt.VC.Type, vc.BaseType) == false {
		return fmt.Errorf("verification failed. missing base type: %s", vc.BaseType)
	}

	if vcjwt.VC.Context == nil || len(vcjwt.VC.Context) == 0 {
		return errors.New("verification failed. missing @context")
	}

	if slices.Contains(vcjwt.VC.Context, vc.BaseContext) == false {
		return fmt.Errorf("verification failed. missing base @context: %s", vc.BaseContext)
	}

	err = vcjwt.JWT.Verify()
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	return nil
}
