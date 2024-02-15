package dns

import (
	"reflect"
	"testing"

	"github.com/alecthomas/assert"
	"golang.org/x/net/dns/dnsmessage"
)

type DHTTXTResourceOpt func() dnsmessage.Resource

func WithDNSRecord(name, body string) DHTTXTResourceOpt {
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
func makeDNSMessage(answersOpt ...DHTTXTResourceOpt) dnsmessage.Message {

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
func Test_parseDNSDID(t *testing.T) {
	tests := map[string]struct {
		msg           dnsmessage.Message
		expectedError string
		assertResult  func(t *testing.T, d *decoder)
	}{
		"basic did with key": {
			msg: makeDNSMessage(
				WithDNSRecord("_did.", "vm=k0;auth=k0;asm=k0;inv=k0;del=k0"),
				WithDNSRecord("_k0._did.", "id=0;t=0;k=YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
			),
			assertResult: func(t *testing.T, d *decoder) {
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
			if test.expectedError != "" {
				assert.EqualError(t, err, test.expectedError)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, "vm=k0;auth=k0;asm=k0;inv=k0;del=k0", dhtDidRecord.rootRecord)

		})
	}
}
