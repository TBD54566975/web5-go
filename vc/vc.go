package vc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/jwt"
)

const (
	BaseContext = "https://www.w3.org/2018/credentials/v1"
	BaseType    = "VerifiableCredential"
)

type DataModel[T any] struct {
	Context           []string `json:"@context"`                 // https://www.w3.org/TR/vc-data-model/#contexts
	Type              []string `json:"type"`                     // https://www.w3.org/TR/vc-data-model/#dfn-type
	Issuer            string   `json:"issuer"`                   // https://www.w3.org/TR/vc-data-model/#issuer
	CredentialSubject T        `json:"credentialSubject"`        // https://www.w3.org/TR/vc-data-model/#credential-subject
	ID                string   `json:"id,omitempty"`             // https://www.w3.org/TR/vc-data-model/#identifiers
	IssuanceDate      string   `json:"issuanceDate"`             // https://www.w3.org/TR/vc-data-model/#issuance-date
	ExpirationDate    string   `json:"expirationDate,omitempty"` // https://www.w3.org/TR/vc-data-model/#expiration
}

type createOptions struct {
	contexts       []string
	types          []string
	id             string
	issuanceDate   time.Time
	expirationDate string
}

type CreateOption func(*createOptions)

func Contexts(contexts ...string) CreateOption {
	return func(o *createOptions) {
		if o.contexts != nil {
			o.contexts = append(o.contexts, contexts...)
		} else {
			o.contexts = contexts
		}
	}
}

func Types(types ...string) CreateOption {
	return func(o *createOptions) {
		if o.types != nil {
			o.types = append(o.types, types...)
		} else {
			o.types = types
		}
	}
}

func ID(id string) CreateOption {
	return func(o *createOptions) {
		o.id = id
	}
}

func IssuanceDate(issuanceDate time.Time) CreateOption {
	return func(o *createOptions) {
		o.issuanceDate = issuanceDate
	}
}

func Create[T any](claims T, opts ...CreateOption) DataModel[T] {
	o := createOptions{
		id:           fmt.Sprintf("urn:vc:uuid:%s", uuid.New().String()),
		contexts:     []string{"https://www.w3.org/2018/credentials/v1"},
		types:        []string{"VerifiableCredential"},
		issuanceDate: time.Now(),
	}

	for _, f := range opts {
		f(&o)
	}

	return DataModel[T]{
		Context:           o.contexts,
		Type:              o.types,
		ID:                o.id,
		IssuanceDate:      o.issuanceDate.UTC().Format(time.RFC3339),
		CredentialSubject: claims,
	}
}

func (vc DataModel[T]) SignJWT(bearerDID did.BearerDID, opts ...jwt.SignOpt) (string, error) {
	vc.Issuer = bearerDID.URI
	jwtClaims := jwt.Claims{Issuer: vc.Issuer}

	t, err := time.Parse(time.RFC3339, vc.IssuanceDate)
	if err != nil {
		return "", fmt.Errorf("failed to parse issuance date: %w", err)
	}

	jwtClaims.IssuedAt = uint64(t.Unix())

	if vc.ExpirationDate != "" {
		t, err := time.Parse(time.RFC3339, vc.ExpirationDate)
		if err != nil {
			return "", fmt.Errorf("failed to parse expiration date: %w", err)
		}

		jwtClaims.Expiration = uint64(t.Unix())
	}

	bytes, err := json.Marshal(vc)
	if err != nil {
		return "", fmt.Errorf("failed to marshal vc: %w", err)
	}

	vcMap := make(map[string]any)
	err = json.Unmarshal(bytes, &vcMap)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal vc: %w", err)
	}

	jwtClaims.Misc = vcMap

	return jwt.Sign(jwtClaims, bearerDID, opts...)
}
