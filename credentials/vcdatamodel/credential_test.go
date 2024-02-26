package vcdatamodel_test

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/assert/v2"
	. "github.com/tbd54566975/web5-go/credentials/vcdatamodel"
)

func TestIDString_MarshalJSON(t *testing.T) {
	expected := "urn:uuid:1234-567..."
	ids := IDString(expected)

	b, err := ids.MarshalJSON()

	assert.NoError(t, err)
	assert.Equal[[]byte](t, []byte(expected), b)
}

func TestIDObject_MarshalJSON(t *testing.T) {
	uuid := "urn:uuid:1234-567..."
	cs := struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}{
		ID:   uuid,
		Name: "bob",
	}

	expected, csErr := json.Marshal(&cs)
	assert.NoError(t, csErr)

	ido := IDObject{
		Id:   uuid,
		Misc: map[string]interface{}{},
	}

	ido.Misc["name"] = cs.Name

	b, err := ido.MarshalJSON()

	assert.NoError(t, err)
	assert.Equal[[]byte](t, []byte(expected), b)
}

func TestCredentialStatus_MarshalJSON(t *testing.T) {
	id := "123"
	csType := "revoked"

	csCust := struct {
		ID             URI    `json:"id"`
		SequenceNumber int16  `json:"sequenceNumber"`
		Type           string `json:"type"`
	}{
		ID:             id,
		Type:           csType,
		SequenceNumber: 1234,
	}

	expected, csErr := json.Marshal(&csCust)
	assert.NoError(t, csErr)

	cs := CredentialStatus{
		StatusReference: StatusReference{
			ID:   id,
			Type: csType,
		},
		Misc: map[string]interface{}{"sequenceNumber": csCust.SequenceNumber},
	}

	actual, err := cs.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal[[]byte](t, expected, actual)
}

func TestCredentialStatus_UnmarshalJSON(t *testing.T) {
	csJson := []byte(`{"id":"123","type":"revoked","sequenceNumber":1234}`)

	expected := CredentialStatus{
		StatusReference: StatusReference{
			ID:   "123",
			Type: "revoked",
		},
		// json unmarshals interface{} into float64 by default
		Misc: map[string]interface{}{"sequenceNumber": float64(1234)},
	}

	var cs CredentialStatus
	err := cs.UnmarshalJSON(csJson)

	assert.NoError(t, err)
	assert.Equal[CredentialStatus](t, expected, cs)
}

func TestVerifiableCredential_UnmarshalJSON_IDString(t *testing.T) {
	vcdmJSON := []byte(`{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"
	],
	"id": "http://example.gov/credentials/3732",
	"type": ["VerifiableCredential", "UniversityDegreeCredential"],
	"issuer": "https://example.edu",
	"issuanceDate": "2010-01-01T19:23:24Z",
	"credentialSubject": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	}`)

	var vcdm VerifiableCredentialDataModel
	err := vcdm.UnmarshalJSON(vcdmJSON)

	// fmt.Printf("%v", vcdm)

	assert.NoError(t, err)
	assert.Equal[string](t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vcdm.CredentialSubject[0].ID())

	// assert that the other fields work as well since we are manually mapping them
	assert.Equal[[]string](t,
		[]string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
		vcdm.Context)
	assert.Equal[string](t, "http://example.gov/credentials/3732", vcdm.ID)
	assert.Equal[string](t, "https://example.edu", vcdm.Issuer)
	assert.Equal[string](t, "2010-01-01T19:23:24Z", vcdm.IssuanceDate)
	assert.Equal[[]string](t, []string{"VerifiableCredential", "UniversityDegreeCredential"}, vcdm.Type)
}

func TestVerifiableCredential_UnmarshalJSON_IDObject(t *testing.T) {
	vcdmJSON := []byte(`{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"
		],
		"id": "http://example.gov/credentials/3732",
		"type": ["VerifiableCredential", "UniversityDegreeCredential"],
		"issuer": "https://example.edu",
		"issuanceDate": "2010-01-01T19:23:24Z",
		"credentialSubject": {
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"degree": {
			"type": "BachelorDegree",
			"name": "Bachelor of Science and Arts"
			}
		}
		}`)

	var vcdm VerifiableCredentialDataModel
	err := vcdm.UnmarshalJSON(vcdmJSON)

	assert.NoError(t, err)
	assert.Equal[string](t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vcdm.CredentialSubject[0].ID())
}

func TestVerifiableCredential_UnmarshalJSON_SliceMixedIDTypes(t *testing.T) {
	// credentialSubject contains both an IDObject and a string here.
	// Both should map properly such that we can call ID() on each of them.
	vcdmJSON := []byte(`{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"
		],
		"id": "http://example.gov/credentials/3732",
		"type": ["VerifiableCredential", "UniversityDegreeCredential"],
		"issuer": "https://example.edu",
		"issuanceDate": "2010-01-01T19:23:24Z",
		"credentialSubject": [{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"degree": {
			"type": "BachelorDegree",
			"name": "Bachelor of Science and Arts"
			}
		}, "did:example:e8d7d9agjasdkfkadkad"]
		}`)

	var vcdm VerifiableCredentialDataModel
	err := vcdm.UnmarshalJSON(vcdmJSON)

	assert.NoError(t, err)
	assert.Equal[string](t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vcdm.CredentialSubject[0].ID())
	assert.Equal[string](t, "did:example:e8d7d9agjasdkfkadkad", vcdm.CredentialSubject[1].ID())
}
