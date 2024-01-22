package dids

// ResolutionResult represents the result of a DID (Decentralized Identifier)
// resolution.
//
// This class encapsulates the metadata and document information obtained as
// a result of resolving a DID. It includes the resolution metadata, the DID
// document (if available), and the document metadata.
//
// The `DidResolutionResult` can be initialized with specific metadata and
// document information, or it can be created with default values if no
// specific information is provided.
type ResolutionResult struct {
	// The metadata associated with the DID resolution process.
	//
	// This includes information about the resolution process itself, such as any errors
	// that occurred. If not provided in the constructor, it defaults to an empty object
	// as per the spec
	ResolutionMetadata ResolutionMetadata `json:"didResolutionMetadata,omitempty"`
	// The resolved DID document, if available.
	//
	// This is the document that represents the resolved state of the DID. It may be `null`
	// if the DID could not be resolved or if the document is not available.
	Document Document `json:"didDocument"`
	// The metadata associated with the DID document.
	//
	// This includes information about the document such as when it was created and
	// any other relevant metadata. If not provided in the constructor, it defaults to an
	// empty `DidDocumentMetadata`.
	DocumentMetadata DocumentMetadata `json:"didDocumentMetadata,omitempty"`
}

// ResolutionResultWithError creates a Resolution Result populated with all default values and the error code provided.
func ResolutionResultWithError(errorCode string) ResolutionResult {
	return ResolutionResult{
		ResolutionMetadata: ResolutionMetadata{
			Error: errorCode,
		},
		DocumentMetadata: DocumentMetadata{},
	}
}

// ResolutionResultWithDocument creates a Resolution Result populated with all default values and the document provided.
func ResolutionResultWithDocument(document Document) ResolutionResult {
	return ResolutionResult{
		ResolutionMetadata: ResolutionMetadata{},
		Document:           document,
		DocumentMetadata:   DocumentMetadata{},
	}
}

// GetError returns the error code associated with the resolution result. returns an empty string if no error code is present.
func (r *ResolutionResult) GetError() string {
	return r.ResolutionMetadata.Error
}
