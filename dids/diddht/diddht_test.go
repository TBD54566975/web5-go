package diddht

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"golang.org/x/net/dns/dnsmessage"
)

type bep44TXTResourceOpt func() dnsmessage.Resource

func WithDNSRecord(name, body string) bep44TXTResourceOpt {
	return func() dnsmessage.Resource {
		return dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name: dnsmessage.MustNewName(name),
				Type: dnsmessage.TypeTXT,
				TTL:  7200,
			},
			Body: &dnsmessage.TXTResource{
				TXT: []string{
					body,
				},
			},
		}
	}
}
func makeDNSMessage(answersOpt ...bep44TXTResourceOpt) dnsmessage.Message {

	answers := []dnsmessage.Resource{}
	for _, a := range answersOpt {
		answers = append(answers, a())
	}

	msg := dnsmessage.Message{
		Header:  dnsmessage.Header{Response: true, Authoritative: true},
		Answers: answers,
	}

	return msg
}

func TestDHTResolve(t *testing.T) {
	// vector taken from https://github.com/TBD54566975/web5-js/blob/dids-new-crypto/packages/crypto/tests/fixtures/test-vectors/secp256k1/bytes-to-public-key.json
	publicKeyHexSecp256k1 := "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
	pubKeyBytesSecp256k1, err := hex.DecodeString(publicKeyHexSecp256k1)
	assert.NoError(t, err)
	base64EncodedSecp256k := base64.RawURLEncoding.EncodeToString(pubKeyBytesSecp256k1)

	tests := map[string]struct {
		didURI               string
		msg                  dnsmessage.Message
		expectedErrorMessage string
		assertResult         func(t *testing.T, d *didcore.Document)
	}{
		"did with valid key and no service": {
			didURI: "did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy",
			msg: makeDNSMessage(
				WithDNSRecord("_did.", "vm=k0;auth=k0;asm=k0;inv=k0;del=k0"),
				WithDNSRecord("_k0._did.", "id=0;t=0;k=YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
			),

			assertResult: func(t *testing.T, d *didcore.Document) {
				assert.False(t, d == nil, "Expected non nil document")
				assert.NotZero(t, d.ID, "Expected DID Document ID to be initialized")
				assert.NotZero(t, d.VerificationMethod, "Expected at least 1 verification method")
			},
		},
		"did with multiple valid keys and no service - out of order verification methods": {
			didURI: "did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy",
			msg: makeDNSMessage(
				WithDNSRecord("_did.", "vm=k0,k1,k2;auth=k0;asm=k1;inv=k2;del=k0"),
				WithDNSRecord("_k0._did.", "id=0;t=0;k=YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
				WithDNSRecord("_k2._did.", fmt.Sprintf("id=2;t=1;k=%s", base64EncodedSecp256k)),
				WithDNSRecord("_k1._did.", fmt.Sprintf("id=1;t=1;k=%s", base64EncodedSecp256k)),
			),

			assertResult: func(t *testing.T, d *didcore.Document) {
				assert.False(t, d == nil, "Expected non nil document")
				assert.NotZero(t, d.ID, "Expected DID Document ID to be initialized")
				assert.Equal[int](t, 3, len(d.VerificationMethod), "Expected 3 verification methods")
			},
		},
		"did with key controller and services": {
			didURI: "did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy",
			msg: makeDNSMessage(
				WithDNSRecord("_did.", "vm=k0;auth=k0;asm=k0;inv=k0;del=k0;srv=s0,s1"),
				WithDNSRecord("_k0._did.", "id=0;t=0;k=YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
				WithDNSRecord("_s0._did.", "id=domain;t=LinkedDomains;se=foo.com"),
				WithDNSRecord("_s1._did.", "id=dwn;t=DecentralizedWebNode;se=https://dwn.tbddev.org/dwn5"),
			),

			assertResult: func(t *testing.T, d *didcore.Document) {
				assert.False(t, d == nil, "Expected non nil document")
				assert.NotZero(t, d.ID, "Expected DID Document ID to be initialized")
				assert.NotZero(t, d.VerificationMethod, "Expected at least 1 verification method")
				assert.Equal[int](t, 2, len(d.Service), "Expected 2 services")
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			buf, err := test.msg.Pack()
			assert.NoError(t, err)
			// test setup
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write(buf)
				assert.NoError(t, err)
			}))
			defer ts.Close()
			r := NewResolver(ts.URL, http.DefaultClient)
			result, err := r.Resolve(test.didURI)

			assert.EqualError(t, err, test.expectedErrorMessage)

			test.assertResult(t, &result.Document)
		})

	}
}

func Test_parseDNSDID(t *testing.T) {
	tests := map[string]struct {
		msg           dnsmessage.Message
		expectedError string
		assertResult  func(t *testing.T, d *dhtDIDRecord)
	}{
		"basic did with key": {
			msg: makeDNSMessage(
				WithDNSRecord("_did.", "vm=k0;auth=k0;asm=k0;inv=k0;del=k0"),
				WithDNSRecord("_k0._did.", "id=0;t=0;k=YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
			),
			assertResult: func(t *testing.T, d *dhtDIDRecord) {
				assert.False(t, d == nil)
				expectedRecords := map[string]string{
					"_k0._did.": "id=0;t=0;k=YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE",
				}
				assert.Equal(t, "vm=k0;auth=k0;asm=k0;inv=k0;del=k0", d.rootRecord)
				assert.True(t, reflect.DeepEqual(expectedRecords, d.records))
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			buf, err := test.msg.Pack()
			assert.NoError(t, err)

			dhtDidRecord, err := parseDNSDID(buf)
			assert.EqualError(t, err, test.expectedError)

			assert.Equal(t, "vm=k0;auth=k0;asm=k0;inv=k0;del=k0", dhtDidRecord.rootRecord)

		})
	}
}
