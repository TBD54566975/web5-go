package vcdatamodel

import (
	"encoding/json"
	"fmt"
)

const (
	DefaultContext = "https://www.w3.org/2018/credentials/v1"
	DefaultVCType  = "VerifiableCredential"
)

type URI = string

type IDType interface {
	json.Marshaler
	ID() string
}

type IDString string

func (id IDString) ID() string {
	return string(id)
}

func (ids IDString) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, ids)), nil
}

type IDObject struct {
	Id   string                 `json:"id"`
	Misc map[string]interface{} `json:"-"`
}

type cpyIDO IDObject

func (ido *IDObject) UnmarshalJSON(data []byte) error {
	cpy := cpyIDO(*ido)
	cpy.Misc = map[string]interface{}{}

	if err := unmarshalMisc(data, &cpy, cpy.Misc, []string{"id"}); err != nil {
		return err
	}

	*ido = IDObject(cpy)
	return nil
}

func (ido IDObject) MarshalJSON() ([]byte, error) {
	copied := cpyID(ido)
	return marshalMisc(copied, &ido.Misc)
}

type cpyID IDObject

func (id IDObject) ID() string {
	return id.Id
}

// A Uniform Resource Identifier, as defined by [RFC3986].
type StatusReference struct {
	ID   URI    `json:"id"`
	Type string `json:"type"`
}

type cpyCrdSts CredentialStatus

// The precise contents of the credential status information is determined by the specific
// credentialStatus type definition, and varies depending on factors such as whether it is
// simple to implement or if it is privacy-enhancing.
type CredentialStatus struct {
	StatusReference
	Misc map[string]interface{} `json:"-"`
}

func (cs *CredentialStatus) UnmarshalJSON(data []byte) error {
	csCpy := cpyCrdSts(*cs)
	csCpy.Misc = map[string]interface{}{}

	if err := unmarshalMisc(data, &csCpy, csCpy.Misc, []string{"id", "type"}); err != nil {
		return err
	}

	*cs = CredentialStatus(csCpy)
	return nil
}

func (cs CredentialStatus) MarshalJSON() ([]byte, error) {
	copied := cpyCrdSts(cs)
	return marshalMisc(copied, &cs.Misc)
}

type CredentialSubject IDType

// This structure is used internally as an intermediate state to enable dynamic unmarshalling
// based on the known fields of a type. Specifically we are concerned about CredentialSubject.
//
// The CredentialSubject field may present in any of the following manners via JSON
// "CredentialSubject": "some id"
// "CredentialSubject": { "id": "some id"}
// "CredentialSubject": ["some id"]
// "CredentialSubject": [{"id": "some id"}]
// "CredentialSubject": ["some id", {"id": "some id"}]
//
// Because all of these are valid, we have to take care while unmarshalling CredentialSubject so
// as not to blow anything up
type verifiableCredentialLD struct {
	Context           []URI              `json:"@context"`
	ID                URI                `json:"id"`
	Type              []URI              `json:"type"`
	CredentialStatus  []CredentialStatus `json:"credentialStatus"`
	CredentialSubject json.RawMessage    `json:"CredentialSubject"`
	ExpirationDate    string             `json:"expirationDate,omitempty"`
	IssuanceDate      string             `json:"issuanceDate"`
	Issuer            string             `json:"issuer"`
}

type VerifiableCredentialDataModel struct {

	// The value of the @context property MUST be an ordered set where the first
	// item is a URI with the value https://www.w3.org/2018/credentials/v1. For reference,
	// a copy of the base context is provided in Appendix B.1 Base Context.
	// Subsequent items in the array MUST express context information and be composed
	// of any combination of URIs or objects.
	Context []URI `json:"@context"`
	// The value of the id property MUST be a single URI.
	ID URI `json:"id"`
	// The value of the type property MUST be, or map to (through interpretation of
	// the @context property), one or more URIs. If more than one URI is provided,
	// the URIs MUST be interpreted as an unordered set.
	Type []URI `json:"type"`
	// This specification defines the following credentialStatus property for the discovery of information about the current
	// status of a verifiable credential, such as whether it is suspended or revoked.
	CredentialStatus []CredentialStatus `json:"credentialStatus,omitempty"`
	// The value of the CredentialSubject property is defined as a set of objects that
	// contain one or more properties that are each related to a subject of the
	// verifiable credential. Each object MAY contain an id, as described in Section 4.2 Identifiers.
	CredentialSubject []CredentialSubject `json:"credentialSubject"`
	// This specification defines the expirationDate property for the expression of credential expiration information.
	// If present, the value of the expirationDate property MUST be a string value of an [XMLSCHEMA11-2] date-time
	// representing the date and time the credential ceases to be valid.
	ExpirationDate string `json:"expirationDate,omitempty"`
	// This specification defines the issuanceDate property for expressing the date and time when a credential becomes valid.
	// A credential MUST have an issuanceDate property. The value of the issuanceDate property MUST
	// be a string value of an [XMLSCHEMA11-2] combined date-time string representing the date and time the
	// credential becomes valid, which could be a date and time in the future. Note that this value represents the earliest
	// point in time at which the information associated with the CredentialSubject property becomes valid.
	IssuanceDate string `json:"issuanceDate"`
	// This specification defines a property for expressing the issuer of a verifiable credential.
	// A verifiable credential MUST have an issuer property.
	Issuer string `json:"issuer"`
}

func (v *VerifiableCredentialDataModel) Validate() error {
	if err := ValidateContext(v.Context); err != nil {
		return err
	}

	if err := ValidateVCType(v.Type); err != nil {
		return err
	}

	if err := ValidateCredentialSubject(v.CredentialSubject); err != nil {
		return err
	}

	return nil
}

func (vc *VerifiableCredentialDataModel) UnmarshalJSON(data []byte) error {
	var vcld verifiableCredentialLD
	if err := json.Unmarshal(data, &vcld); err != nil {
		return err
	}

	// map our vc
	v := cpyVC{}
	v.Context = vcld.Context
	v.ID = vcld.ID
	v.Issuer = vcld.Issuer
	v.IssuanceDate = vcld.IssuanceDate
	v.CredentialStatus = vcld.CredentialStatus
	v.ExpirationDate = vcld.ExpirationDate
	v.Type = vcld.Type

	// use our intermediate object to start marshalling our id type
	if isJSONArray(vcld.CredentialSubject) {
		var sj []json.RawMessage
		if err := json.Unmarshal(vcld.CredentialSubject, &sj); err != nil {
			return err
		}

		for _, id := range sj {
			idType, err := idType(id)
			if err != nil {
				return err
			}

			v.CredentialSubject = append(v.CredentialSubject, idType)
		}
	} else {
		idType, err := idType(vcld.CredentialSubject)
		if err != nil {
			return err
		}

		v.CredentialSubject = append(v.CredentialSubject, idType)
	}

	*vc = VerifiableCredentialDataModel(v)

	return nil
}

func idType(data []byte) (IDType, error) {
	if isJSONObj(data) {
		var idObj IDObject
		if err := json.Unmarshal(data, &idObj); err != nil {
			return nil, err
		}

		return idObj, nil
	} else {
		var idStr IDString
		if err := json.Unmarshal(data, &idStr); err != nil {
			return nil, err
		}

		return idStr, nil
	}
}

// leveraging pattern laid out in jwt.go file for Claims
type cpyVC VerifiableCredentialDataModel
