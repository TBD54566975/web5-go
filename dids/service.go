package dids

// Service is used in DID documents to express ways of communicating with
// the DID subject or associated entities.
// A service can be any type of service the DID subject wants to advertise.
//
// Specification Reference: https://www.w3.org/TR/did-core/#services
type Service struct {
	// Id is the value of the id property and MUST be a URI conforming to RFC3986.
	// A conforming producer MUST NOT produce multiple service entries with
	// the same id. A conforming consumer MUST produce an error if it detects
	// multiple service entries with the same id.
	ID string `json:"id"`

	// Type is an example of registered types which can be found
	// here: https://www.w3.org/TR/did-spec-registries/#service-types
	Type string `json:"type"`

	// ServiceEndpoint is a network address, such as an HTTP URL, at which services
	// operate on behalf of a DID subject.
	ServiceEndpoint string `json:"serviceEndpoint"`
}
