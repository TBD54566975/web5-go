package dids

// ResolutionMetadata is a metadata structure consisting of values relating to the results of the
// DID resolution process which typically changes between invocations of the
// resolve and resolveRepresentation functions, as it represents data about
// the resolution process itself
//
// Spec: https://www.w3.org/TR/did-core/#dfn-didresolutionmetadata
type ResolutionMetadata struct {
	// The Media Type of the returned didDocumentStream. This property is
	// REQUIRED if resolution is successful and if the resolveRepresentation
	// function was called
	ContentType string `json:"contentType,omitempty"`

	// The error code from the resolution process. This property is REQUIRED
	// when there is an error in the resolution process. The value of this
	// property MUST be a single keyword ASCII string. The possible property
	// values of this field SHOULD be registered in the
	// [DID Specification Registries](https://www.w3.org/TR/did-spec-registries/#error)
	Error string `json:"error,omitempty"`
}
