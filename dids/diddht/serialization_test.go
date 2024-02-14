package diddht

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"golang.org/x/net/dns/dnsmessage"
)

func Test_MarshalDIDDocument(t *testing.T) {

	var didDoc didcore.Document
	assert.NoError(t, json.Unmarshal([]byte(`
	{
		"id": "did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy",
		"verificationMethod": [
		{
			"id": "did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy#0",
			"type": "JsonWebKey2020",
			"controller": "did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy",
			"publicKeyJwk": {
			"crv": "Ed25519",
			"kty": "OKP",
			"kid": "0",
			"x": "ZR8A7IHnJ5v9-TFcDzI8cZfhGJzSj29LYutpKTLwdoo"
			}
		}
		],
		"authentication": [
		"did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy#0"
		],
		"assertionMethod": [
		"did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy#0"
		],
		"capabilityInvocation": [
		"did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy#0"
		],
		"capabilityDelegation": [
		"did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy#0"
		]
	}
	`), &didDoc))

	assert.NotZero(t, didDoc.VerificationMethod)
	msg := dnsmessage.Message{}
	assert.NoError(t, MarshalDIDDocument(&didDoc, &msg))

	assert.Equal(t, len(msg.Answers), 2)

	buf, _ := msg.Pack()
	rec, _ := parseDNSDID(buf)
	fmt.Println(rec)
	reParsedDoc, err := rec.DIDDocument("did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy")
	assert.NoError(t, err)
	assert.NotZero(t, reParsedDoc)
	assert.Equal(t, &didDoc, reParsedDoc)
}
