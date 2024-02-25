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
	vcDataModel *vcdm.VerifiableCredentialDataModel
}

func (v *VerifiableCredential) MarhsalJSON() ([]byte, error) {
	return json.Marshal(v.vcDataModel)
}

type signVCOptions struct {
	did      did.BearerDID
	signOpts []jwt.SignOpt
}

func (v *VerifiableCredential) Sign(o *signVCOptions) (string, error) {
	if err := v.vcDataModel.Validate(); err != nil {
		return "", err
	}

	claims := jwt.Claims{
		Issuer:  v.vcDataModel.Issuer,
		Subject: v.vcDataModel.CredentialSubject[0].ID(),
		Misc:    map[string]interface{}{"vc": v.vcDataModel},
	}

	return jwt.Sign(claims, o.did, o.signOpts...)
}

func (u *VerifiableCredential) Verify(vcjwt string) (*jwt.Claims, error) {
	var decoded *jwt.Decoded
	if d, err := jwt.Verify(vcjwt); err != nil {
		decoded = &d
		return nil, err
	}

	vcRaw, ok := decoded.Claims.Misc["vc"]
	if !ok {
		return nil, errors.New("JWT payload missing 'vc' property")
	}

	vc, ok := vcRaw.(VerifiableCredential)
	if !ok {
		return nil, errors.New("JWT payload entry 'vc' is invalid type")
	}

	if err := vc.vcDataModel.Validate(); err != nil {
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

type createCredentialOptions struct {
	vcType         []vcdm.URI
	issuer         string
	subject        []vcdm.CredentialSubject
	issuanceDate   string
	expirationDate string
}

func (o *createCredentialOptions) CreateVerifiableCredential() (*VerifiableCredential, error) {
	if o.issuer == "" || len(o.subject) == 0 {
		return nil, errors.New("Issuer and subject must be defined")
	}

	if o.issuanceDate == "" {
		t := time.Now()
		xmlFmt := "2006-01-02T15:04:05Z"
		o.issuanceDate = t.Format(xmlFmt)
	}

	vcdm := &vcdm.VerifiableCredentialDataModel{
		Context:           []vcdm.URI{vcdm.DefaultContext},
		Type:              o.vcType,
		ID:                fmt.Sprintf("urn:uuid:%s", crypto.RandomUUID()),
		Issuer:            o.issuer,
		IssuanceDate:      o.issuanceDate,
		CredentialSubject: o.subject,
		ExpirationDate:    o.expirationDate,
	}

	vc := &VerifiableCredential{
		vcDataModel: vcdm,
	}

	if err := vc.vcDataModel.Validate(); err != nil {
		return nil, err
	}

	return vc, nil
}
