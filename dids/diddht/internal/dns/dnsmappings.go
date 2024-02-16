package dns

import (
	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/dids/didcore"
)

// vmPurposeDNStoDID maps the DNS representation of the
// verification method relationships to the DID representation.
//
// https://did-dht.com/#verification-relationship-index
var vmPurposeDNStoDID = map[string]didcore.Purpose{
	DNSLabelAuthentication:       didcore.PurposeAuthentication,
	DNSLabelAssertionMethod:      didcore.PurposeAssertion,
	DNSLabelKeyAgreement:         didcore.PurposeKeyAgreement,
	DNSLabelCapabilityInvocation: didcore.PurposeCapabilityInvocation,
	DNSLabelCapabilityDeletion:   didcore.PurposeCapabilityDelegation,
}

// dhtIndexToAlg maps the DNS representation of the key type index
// to the algorithm ID.
//
// https://did-dht.com/registry/index.html#key-type-index
var dhtIndexToAlg = map[string]string{
	"0": dsa.AlgorithmIDED25519,
	"1": dsa.AlgorithmIDSECP256K1,
}

// algToDhtIndex maps the DID representation of the key type (algorithm)
// to the DNS key type index.
//
// https://did-dht.com/registry/index.html#key-type-index
var algToDhtIndex = map[string]string{
	dsa.AlgorithmIDED25519:   "0",
	dsa.AlgorithmIDSECP256K1: "1",
}
