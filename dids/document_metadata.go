package dids

// DocumentMetadata contains metadata about the DID Document
// This metadata typically does not change between invocations of
// the resolve and resolveRepresentation functions unless the DID document
// changes, as it represents metadata about the DID document.
//
// Spec: https://www.w3.org/TR/did-core/#dfn-diddocumentmetadata
type DocumentMetadata struct {
	// timestamp of the Create operation. The value of the property MUST be a
	// string formatted as an XML Datetime normalized to UTC 00:00:00 and
	// without sub-second decimal precision. For example: 2020-12-20T19:17:47Z.
	Created string `json:"created,omitempty"`
	// timestamp of the last Update operation for the document version which was
	// resolved. The value of the property MUST follow the same formatting rules
	// as the created property. The updated property is omitted if an Update
	// operation has never been performed on the DID document. If an updated
	// property exists, it can be the same value as the created property
	// when the difference between the two timestamps is less than one second.
	Updated string `json:"updated,omitempty"`
	// If a DID has been deactivated, DID document metadata MUST include this
	// property with the boolean value true. If a DID has not been deactivated,
	// this property is OPTIONAL, but if included, MUST have the boolean value
	// false.
	Deactivated bool `json:"deactivated,omitempty"`
	// indicates the version of the last Update operation for the document version
	// which was resolved.
	VersionID string `json:"versionId,omitempty"`
	// indicates the timestamp of the next Update operation. The value of the
	// property MUST follow the same formatting rules as the created property.
	NextUpdate string `json:"nextUpdate,omitempty"`
	// if the resolved document version is not the latest version of the document.
	// It indicates the timestamp of the next Update operation. The value of the
	// property MUST follow the same formatting rules as the created property.
	NextVersionID string `json:"nextVersionId,omitempty"`
	// A DID method can define different forms of a DID that are logically
	// equivalent. An example is when a DID takes one form prior to registration
	// in a verifiable data registry and another form after such registration.
	// In this case, the DID method specification might need to express one or
	// more DIDs that are logically equivalent to the resolved DID as a property
	// of the DID document. This is the purpose of the equivalentId property.
	EquivalentID string `json:"equivalentId,omitempty"`
	// The canonicalId property is identical to the equivalentId property except:
	//   * it is associated with a single value rather than a set
	//   * the DID is defined to be the canonical ID for the DID subject within
	//     the scope of the containing DID document.
	CanonicalID string `json:"canonicalId,omitempty"`
}
