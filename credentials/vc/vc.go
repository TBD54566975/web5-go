package vc

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	vcdm "github.com/tbd54566975/web5-go/credentials/vcdatamodel"
	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/jwt"
)

type VerifiableCredential struct {
	VCDataModel *vcdm.VerifiableCredentialDataModel
}

func (v *VerifiableCredential) UnmarshalJSON(data []byte) error {
	v.VCDataModel = &vcdm.VerifiableCredentialDataModel{}
	return v.VCDataModel.UnmarshalJSON(data)
}

func (v VerifiableCredential) MarhsalJSON() ([]byte, error) {
	return json.Marshal(v.VCDataModel)
}

type SignVCOptions struct {
	DID      did.BearerDID
	SignOpts []jwt.SignOpt
}

func (v *VerifiableCredential) Create(o CreateCredentialOptions) error {
	vc, err := o.CreateVerifiableCredential()
	if err != nil {
		return err
	}

	*v = *vc
	return nil
}

func (v *VerifiableCredential) Sign(o *SignVCOptions) (string, error) {
	// this is only being called in case some user is creating a VC by hand without create options
	if err := v.VCDataModel.Validate(); err != nil {
		return "", err
	}

	claims := jwt.Claims{
		Issuer:  v.VCDataModel.Issuer,
		Subject: v.VCDataModel.CredentialSubject[0].ID(),
		Misc:    map[string]interface{}{"vc": v.VCDataModel},
	}

	return jwt.Sign(claims, o.DID, o.SignOpts...)
}

func (u *VerifiableCredential) Verify(vcjwt string) (*jwt.Claims, error) {
	decoded, err := jwt.Verify(vcjwt)

	if err != nil {
		return nil, err
	}

	vcRaw, ok := decoded.Claims.Misc["vc"]
	if !ok {
		return nil, errors.New("JWT payload missing 'vc' property")
	}

	vcStr, err := json.Marshal(vcRaw)

	if err != nil {
		return nil, err
	}

	var vc VerifiableCredential
	if err := json.Unmarshal(vcStr, &vc); err != nil {
		return nil, errors.New("JWT payload entry 'vc' is invalid type")
	}

	if err := vc.VCDataModel.Validate(); err != nil {
		return nil, err
	}

	misc := decoded.Claims.Misc
	misc["vc"] = vc
	claims := &jwt.Claims{
		Issuer:  decoded.Claims.Issuer,
		Subject: decoded.Claims.Subject,
		Misc:    misc,
	}

	return claims, nil
}

type CreateCredentialOptions struct {
	VCType         []vcdm.URI
	Issuer         string
	Subject        []vcdm.CredentialSubject
	IssuanceDate   string
	ExpirationDate string
}

func (o *CreateCredentialOptions) CreateVerifiableCredential() (*VerifiableCredential, error) {
	if o.Issuer == "" || len(o.Subject) == 0 {
		return nil, errors.New("Issuer and subject must be defined")
	}

	if o.IssuanceDate == "" {
		t := time.Now()
		xmlFmt := "2006-01-02T15:04:05Z"
		o.IssuanceDate = t.Format(xmlFmt)
	}

	vcdm := &vcdm.VerifiableCredentialDataModel{
		Context:           []vcdm.URI{vcdm.DefaultContext},
		Type:              o.VCType,
		ID:                fmt.Sprintf("urn:uuid:%s", crypto.RandomUUID()),
		Issuer:            o.Issuer,
		IssuanceDate:      o.IssuanceDate,
		CredentialSubject: o.Subject,
		ExpirationDate:    o.ExpirationDate,
	}

	vc := &VerifiableCredential{
		VCDataModel: vcdm,
	}

	if err := vc.VCDataModel.Validate(); err != nil {
		return nil, err
	}

	return vc, nil
}
