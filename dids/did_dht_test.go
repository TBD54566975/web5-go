package dids

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/alecthomas/assert/v2"
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

	tests := map[string]struct {
		msg           dnsmessage.Message
		expectedError error
		assertResult  func(t *testing.T, d *Document)
	}{
		"basic did with key": {
			msg: makeDNSMessage(
				WithDNSRecord("_did.", "vm=k0;auth=k0;asm=k0;inv=k0;del=k0"),
				WithDNSRecord("_k0._did.", "id=0;t=0;k=YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
			),
			expectedError: nil,
			assertResult: func(t *testing.T, d *Document) {
				assert.False(t, d == nil, "Expected non nil document")
				assert.NotZero[string](t, d.ID, "Expected DID Document ID to be initialized")
				assert.NotZero[[]VerificationMethod](t, d.VerificationMethod, "Expected at least 1 verification method")
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

			document, err := ResolveDIDDHT("did:dht:cwxob5rbhhu3z9x3gfqy6cthqgm6ngrh4k8s615n7pw11czoq4fy", ts.URL, http.DefaultClient)

			if test.expectedError != nil {
				assert.Error(t, test.expectedError, err)
				return
			}

			test.assertResult(t, document)
		})

	}
}

func Test_parseDNSDID(t *testing.T) {
	tests := map[string]struct {
		msg           dnsmessage.Message
		expectedError error
		assertResult  func(t *testing.T, d *dhtDIDRecord)
	}{
		"basic did with key": {
			msg: makeDNSMessage(
				WithDNSRecord("_did.", "vm=k0;auth=k0;asm=k0;inv=k0;del=k0"),
				WithDNSRecord("_k0._did.", "id=0;t=0;k=YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
			),
			expectedError: nil,
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
			if test.expectedError != nil {
				assert.Error(t, test.expectedError, err)
				return
			}

			assert.Equal(t, "vm=k0;auth=k0;asm=k0;inv=k0;del=k0", dhtDidRecord.rootRecord)

		})
	}
}
