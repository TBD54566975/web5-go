package dids

// Document represents a set of data describing the DID subject including mechanisms such as:
//   - cryptographic public keys - used to authenticate itself and prove
//     association with the DID
//   - services - means of communicating or interacting with the DID subject or
//     associated entities via one or more service endpoints.
//     Examples include discovery services, agent services,
//     social networking services, file storage services,
//     and verifiable credential repository services.
//
// A DID Document can be retrieved by resolving a DID URI.
type Document struct {
	// Context is a URI that defines the schema version used in the document.
	Context string `json:"@context,omitempty"`

	// Id is the DID URI for a particular DID subject, expressed using the id property in the DID document.
	ID string `json:"id"`

	// AlsoKnownAs can contain multiple identifiers for different purposes, or at different times for the same DID subject.
	// The assertion that two or more DIDs (or other types of URI) refer to the same DID subject can be made using the alsoKnownAs property.
	AlsoKnownAs []string `json:"alsoKnownAs,omitempty"`

	// Controller defines an entity that is authorized to make changes to a DID document.
	// The process of authorizing a DID controller is defined by the DID method.
	// It can be a string or a list of strings.
	// TODO: figure out how to handle string or list of strings
	Controller []string `json:"controller,omitempty"`

	// VerificationMethod is a list of cryptographic public keys, which can be used to authenticate or authorize
	// interactions with the DID subject or associated parties.
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`

	// Service expresses ways of communicating with the DID subject or associated entities.
	// A service can be any type of service the DID subject wants to advertise.
	// spec reference: https://www.w3.org/TR/did-core/#verification-methods
	Service []Service `json:"service,omitempty"`

	// AssertionMethod is used to specify how the DID subject is expected to express claims,
	// such as for the purposes of issuing a Verifiable Credential.
	AssertionMethod []string `json:"assertionMethod,omitempty"`

	// Authentication specifies how the DID subject is expected to be authenticated,
	// for purposes such as logging into a website or engaging in any sort of challenge-response protocol.
	Authentication []string `json:"authentication,omitempty"`

	// KeyAgreement specifies how an entity can generate encryption material to transmit confidential
	// information intended for the DID subject, such as for establishing a secure communication channel.
	KeyAgreement []string `json:"keyAgreement,omitempty"`

	// CapabilityDelegation specifies a mechanism used by the DID subject to delegate a
	// cryptographic capability to another party, such as delegating the authority to access a specific HTTP API.
	CapabilityDelegation []string `json:"capabilityDelegation,omitempty"`

	// CapabilityInvocation specifies a verification method used by the DID subject to invoke a
	// cryptographic capability, such as the authorization to update the DID Document.
	CapabilityInvocation []string `json:"capabilityInvocation,omitempty"`
}

type addVMOptions struct {
	purposes []string
}

type AddVMOption func(o *addVMOptions)

func Purposes(r ...string) AddVMOption {
	return func(o *addVMOptions) {
		o.purposes = r
	}
}

// AddVerificationMethod adds a verification method to the document. if Purposes are provided,
// the verification method's ID will be added to the corresponding list of purposes.
func (d *Document) AddVerificationMethod(method VerificationMethod, opts ...AddVMOption) {
	o := &addVMOptions{purposes: []string{}}
	for _, opt := range opts {
		opt(o)
	}

	d.VerificationMethod = append(d.VerificationMethod, method)

	for _, p := range o.purposes {
		switch p {
		case "assertionMethod":
			d.AssertionMethod = append(d.AssertionMethod, method.ID)
		case "authentication":
			d.Authentication = append(d.Authentication, method.ID)
		case "keyAgreement":
			d.KeyAgreement = append(d.KeyAgreement, method.ID)
		case "capabilityDelegation":
			d.CapabilityDelegation = append(d.CapabilityDelegation, method.ID)
		case "capabilityInvocation":
			d.CapabilityInvocation = append(d.CapabilityInvocation, method.ID)
		}
	}
}
