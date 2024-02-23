package vc

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/tbd54566975/web5-go/jwt"
)

func DecodeJWT[T CredentialSubject](vcJWT string) (DecodedJWT[T], error) {
	decoded, err := jwt.Decode(vcJWT)
	if err != nil {
		return DecodedJWT[T]{}, fmt.Errorf("failed to decode vc-jwt: %w", err)
	}

	if decoded.Claims.Misc == nil {
		return DecodedJWT[T]{}, fmt.Errorf("vc-jwt missing vc claim")
	}

	bytes, err := json.Marshal(decoded.Claims.Misc["vc"])
	if err != nil {
		return DecodedJWT[T]{}, fmt.Errorf("failed to marshal vc claim: %w", err)
	}

	var vc DataModel[T]
	if err := json.Unmarshal(bytes, &vc); err != nil {
		return DecodedJWT[T]{}, fmt.Errorf("failed to unmarshal vc claim: %w", err)
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

	return DecodedJWT[T]{
		JWT: decoded,
		VC:  vc,
	}, nil

}

type DecodedJWT[T CredentialSubject] struct {
	JWT jwt.Decoded
	VC  DataModel[T]
}

func (vcjwt DecodedJWT[T]) verify() error {
	if vcjwt.VC.Issuer == "" {
		return fmt.Errorf("vc-jwt missing issuer")
	}

	if vcjwt.VC.ID == "" {
		return fmt.Errorf("vc-jwt missing id")
	}

	if vcjwt.VC.IssuanceDate == "" {
		return fmt.Errorf("vc-jwt missing issuance date")
	}

	if vcjwt.VC.ExpirationDate != "" {
		exp, err := time.Parse(time.RFC3339, vcjwt.VC.ExpirationDate)
		if err != nil {
			return fmt.Errorf("failed to parse expiration date: %w", err)
		}

		if time.Now().After(exp) {
			return fmt.Errorf("vc-jwt has expired")
		}
	}

	if vcjwt.VC.Type == nil || len(vcjwt.VC.Type) == 0 {
		return fmt.Errorf("vc-jwt missing type")
	}

	if slices.Contains(vcjwt.VC.Type, BaseType) == false {
		return fmt.Errorf("vc-jwt missing %s type", BaseType)
	}

	if vcjwt.VC.Context == nil || len(vcjwt.VC.Context) == 0 {
		return fmt.Errorf("vc-jwt missing @context")
	}

	if slices.Contains(vcjwt.VC.Context, BaseContext) == false {
		return fmt.Errorf("vc-jwt missing %s context", BaseContext)
	}

	err := vcjwt.JWT.Verify()
	if err != nil {
		return fmt.Errorf("failed to verify vc-jwt: %w", err)
	}

	return nil
}
