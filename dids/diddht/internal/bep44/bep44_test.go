package bep44

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func Test_newSignedBEP44Message(t *testing.T) {
	payload := []byte(`a=1,b=2,c=3`)

	type args struct {
		payload        []byte
		seq            int64
		publicKeyBytes []byte
		signer         Signer
	}
	tests := map[string]struct {
		args    args
		wantErr bool
	}{
		"good - create signed message and decode payload": {
			args: args{
				payload:        payload,
				seq:            time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC).Unix() / 1000,
				publicKeyBytes: []byte("YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
				signer: func(payload []byte) ([]byte, error) {
					return append(payload, []byte("signed")...), nil
				},
			},
		},
		"bad - signer fails": {
			args: args{
				payload:        payload,
				seq:            time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC).Unix() / 1000,
				publicKeyBytes: []byte("YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE"),
				signer: func(payload []byte) ([]byte, error) {
					return nil, errors.New("signer failed")
				},
			},
			wantErr: true,
		},
	}

	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			got, err := NewMessage(tt.args.payload, tt.args.seq, tt.args.publicKeyBytes, tt.args.signer)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				return
			}
			assert.True(t, strings.HasSuffix(string(got.sig), "signed"))
			assert.Equal(t, tt.args.publicKeyBytes, got.k)

			decodedPayload, err := got.DecodePayload()
			assert.NoError(t, err)
			assert.Equal(t, tt.args.payload, decodedPayload)
		})
	}
}
