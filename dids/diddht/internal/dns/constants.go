package dns

const (
	// Labels for the dns representation of the verification method purposes

	// DNSLabelAuthentication is the DNS representation of the authentication purpose
	DNSLabelAuthentication = "auth"

	// DNSLabelAssertionMethod is the DNS representation of the assertion method purpose
	DNSLabelAssertionMethod = "asm"

	// DNSLabelCapabilityDeletion is the DNS representation of the capability delegation purpose
	DNSLabelCapabilityDeletion = "del"

	// DNSLabelCapabilityInvocation is the DNS representation of the capability invocation purpose
	DNSLabelCapabilityInvocation = "inv"

	// DNSLabelKeyAgreement is the DNS representation of the key agreement purpose
	DNSLabelKeyAgreement = "agm"
)
