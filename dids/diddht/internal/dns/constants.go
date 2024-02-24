package dns

const (
	// Labels for the dns representation of the verification method purposes

	// PurposeAuthentication is the DNS representation of the authentication purpose
	PurposeAuthentication = "auth"

	// PurposeAssertionMethod is the DNS representation of the assertion method purpose
	PurposeAssertionMethod = "asm"

	// PurposeCapabilityDeletion is the DNS representation of the capability delegation purpose
	PurposeCapabilityDeletion = "del"

	// PurposeCapabilityInvocation is the DNS representation of the capability invocation purpose
	PurposeCapabilityInvocation = "inv"

	// PurposeKeyAgreement is the DNS representation of the key agreement purpose
	PurposeKeyAgreement = "agm"

	// Labels for other properties

	// DNSLabelVerificationMethod is the DNS representation of the verification method property
	DNSLabelVerificationMethod = "vm"

	// DNSLabelService is the DNS representation of the service property
	DNSLabelService = "srv"

	// DNSLabelController is the DNS representation of the controller property
	DNSLabelController = "cnt"

	// DNSLabelAlsoKnownAs is the DNS representation of the AKA property
	DNSLabelAlsoKnownAs = "aka"
)
