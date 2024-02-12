package diddht

import (
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func Test_newSignedBEP44Message(t *testing.T) {
	msg := makeDNSMessage(
		WithDNSRecord("_did.", "vm=k0;auth=k0;asm=k0;inv=k0;del=k0"),
		WithDNSRecord("_k0._did.", "id=0;t=0;k=YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
	)

	dnsPayload, _ := msg.Pack()

	type args struct {
		dnsPayload     []byte
		seq            int64
		publicKeyBytes []byte
		signer         signer
	}
	tests := map[string]struct {
		args    args
		wantErr bool
	}{
		"success": {
			args: args{
				dnsPayload:     dnsPayload,
				seq:            time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC).Unix() / 1000,
				publicKeyBytes: []byte("YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
				signer: func(payload []byte) ([]byte, error) {
					return append(payload, []byte("signed")...), nil
				},
			},
		},
	}

	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			got, err := newSignedBEP44Message(tt.args.dnsPayload, tt.args.seq, tt.args.publicKeyBytes, tt.args.signer)
			assert.Equal(t, tt.wantErr, err != nil)
			assert.True(t, strings.HasSuffix(string(got.sig), "signed"))
			assert.Equal(t, tt.args.publicKeyBytes, got.k)
		})
	}
}
