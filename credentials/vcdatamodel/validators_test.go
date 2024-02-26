package vcdatamodel_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	. "github.com/tbd54566975/web5-go/credentials/vcdatamodel"
)

func TestValidateContext(t *testing.T) {
	c := []URI{DefaultCredsContext}

	err := ValidateContext(c)

	assert.NoError(t, err)
}

func TestValidateContext_MissingDefault(t *testing.T) {
	c := []URI{"http://wrong", "http://wrong/again"}

	err := ValidateContext(c)

	assert.Error(t, err)
}

func TestValidateVCType(t *testing.T) {
	vcType := []string{DefaultVCType}

	err := ValidateVCType(vcType)

	assert.NoError(t, err)
}

func TestValidateVCType_NoVC(t *testing.T) {
	vcType := []string{"NotVerifiableCredential"}

	err := ValidateVCType(vcType)

	assert.Error(t, err)
}

func TestValidateCredentialSubject(t *testing.T) {
	subject := []CredentialSubject{IDString("urn:uuid:abcd-ef123-4567")}

	err := ValidateCredentialSubject(subject)

	assert.NoError(t, err)
}

func TestValidateCredentialSubject_NoSubjects(t *testing.T) {
	subject := []CredentialSubject{}

	err := ValidateCredentialSubject(subject)

	assert.Error(t, err)
}
