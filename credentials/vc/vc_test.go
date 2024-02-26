package vc_test

import (
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	. "github.com/tbd54566975/web5-go/credentials/vc"
	vcdm "github.com/tbd54566975/web5-go/credentials/vcdatamodel"
	"github.com/tbd54566975/web5-go/dids/didjwk"
)

func TestVerifiableCredential_Create(t *testing.T) {
	types := []vcdm.URI{"VerifiableCredential", "UniversityDegreeCredential"}
	issuer := "https://example.edu"
	subjectID := "did:example:ebfeb1f712ebc6f1c276e12ec21"
	issuanceDate := "2010-01-01T19:23:24Z"
	expirationDate := "2039-12-31T19:23:24Z"

	o := CreateCredentialOptions{
		VCType:         types,
		Issuer:         issuer,
		Subject:        []vcdm.CredentialSubject{vcdm.IDString(subjectID)},
		IssuanceDate:   issuanceDate,
		ExpirationDate: expirationDate,
	}

	var vc VerifiableCredential
	err := vc.Create(o)

	assert.NoError(t, err)
	assert.Equal(t, []vcdm.URI{vcdm.DefaultContext}, vc.VCDataModel.Context)
	assert.Equal(t, types, vc.VCDataModel.Type)
	assert.NotZero(t, vc.VCDataModel.ID)
	assert.Equal(t, issuer, vc.VCDataModel.Issuer)
	assert.Equal(t, issuanceDate, vc.VCDataModel.IssuanceDate)
	assert.Equal(t, expirationDate, vc.VCDataModel.ExpirationDate)
}

func TestVerifiableCredential_Create_NoIssuanceDate(t *testing.T) {
	types := []vcdm.URI{"VerifiableCredential", "UniversityDegreeCredential"}
	issuer := "https://example.edu"
	subjectID := "did:example:ebfeb1f712ebc6f1c276e12ec21"

	o := CreateCredentialOptions{
		VCType:  types,
		Issuer:  issuer,
		Subject: []vcdm.CredentialSubject{vcdm.IDString(subjectID)},
	}

	var vc VerifiableCredential
	err := vc.Create(o)
	_, issErr := time.Parse("2006-01-02T15:04:05Z", vc.VCDataModel.IssuanceDate)

	assert.NoError(t, err)
	assert.NoError(t, issErr)
	assert.NotZero(t, vc.VCDataModel.IssuanceDate)
}

func TestVerifiableCredential_Create_NoIssuer(t *testing.T) {
	types := []vcdm.URI{"VerifiableCredential", "UniversityDegreeCredential"}
	subjectID := "did:example:ebfeb1f712ebc6f1c276e12ec21"

	o := CreateCredentialOptions{
		VCType:  types,
		Subject: []vcdm.CredentialSubject{vcdm.IDString(subjectID)},
	}

	var vc VerifiableCredential
	err := vc.Create(o)

	assert.Error(t, err)
}

func TestVerifiableCredential_Create_NoSubject(t *testing.T) {
	types := []vcdm.URI{"VerifiableCredential", "UniversityDegreeCredential"}
	issuer := "https://example.edu"

	o := CreateCredentialOptions{
		VCType: types,
		Issuer: issuer,
	}

	var vc VerifiableCredential
	err := vc.Create(o)

	assert.Error(t, err)
}

func TestVerifiableCredential_Create_InvalidType(t *testing.T) {
	types := []vcdm.URI{"UniversityDegreeCredential"}
	issuer := "https://example.edu"
	subjectID := "did:example:ebfeb1f712ebc6f1c276e12ec21"

	o := CreateCredentialOptions{
		VCType:  types,
		Issuer:  issuer,
		Subject: []vcdm.CredentialSubject{vcdm.IDString(subjectID)},
	}

	var vc VerifiableCredential
	err := vc.Create(o)

	assert.Error(t, err)
}

func TestVerifiableCredential_Sign(t *testing.T) {
	types := []vcdm.URI{"VerifiableCredential", "UniversityDegreeCredential"}
	issuer := "https://example.edu"
	subjectID := "did:example:ebfeb1f712ebc6f1c276e12ec21"
	issuanceDate := "2010-01-01T19:23:24Z"
	expirationDate := "2039-12-31T19:23:24Z"

	bearerDID, didErr := didjwk.Create()

	o := CreateCredentialOptions{
		VCType:         types,
		Issuer:         issuer,
		Subject:        []vcdm.CredentialSubject{vcdm.IDString(subjectID)},
		IssuanceDate:   issuanceDate,
		ExpirationDate: expirationDate,
	}

	var vc VerifiableCredential
	err := vc.Create(o)

	signed, signErr := vc.Sign(&SignVCOptions{
		DID: bearerDID,
	})

	assert.NoError(t, err)
	assert.NoError(t, didErr)
	assert.NoError(t, signErr)
	assert.NotZero(t, signed)
}

func TestVerifiableCredential_Sign_ValidateFails(t *testing.T) {
	bearerDID, didErr := didjwk.Create()

	vc := VerifiableCredential{VCDataModel: &vcdm.VerifiableCredentialDataModel{}}

	_, signErr := vc.Sign(&SignVCOptions{
		DID: bearerDID,
	})

	assert.NoError(t, didErr)
	assert.Error(t, signErr)
}

func TestVerifiableCredential_Verify(t *testing.T) {
	types := []vcdm.URI{"VerifiableCredential", "UniversityDegreeCredential"}
	issuer := "https://example.edu"
	subjectID := "did:example:ebfeb1f712ebc6f1c276e12ec21"
	issuanceDate := "2010-01-01T19:23:24Z"
	expirationDate := "2039-12-31T19:23:24Z"

	bearerDID, didErr := didjwk.Create()

	o := CreateCredentialOptions{
		VCType:         types,
		Issuer:         issuer,
		Subject:        []vcdm.CredentialSubject{vcdm.IDString(subjectID)},
		IssuanceDate:   issuanceDate,
		ExpirationDate: expirationDate,
	}

	var vc VerifiableCredential
	err := vc.Create(o)

	signed, signErr := vc.Sign(&SignVCOptions{
		DID: bearerDID,
	})

	claims, verifyErr := vc.Verify(signed)

	cvc, ok := claims.Misc["vc"].(VerifiableCredential)

	assert.True(t, ok)
	assert.NoError(t, err)
	assert.NoError(t, didErr)
	assert.NoError(t, signErr)
	assert.NoError(t, verifyErr)
	assert.Equal(t, issuer, claims.Issuer)
	assert.Equal(t, subjectID, claims.Subject)
	assert.Equal(t, vc.VCDataModel, cvc.VCDataModel)
}
