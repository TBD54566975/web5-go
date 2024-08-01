package did_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/did"
)

type vector struct {
	input  string
	output map[string]interface{}
	error  bool
}

func TestParse(t *testing.T) {
	vectors := []vector{
		{input: "", error: true},
		{input: "did:", error: true},
		{input: "did:uport", error: true},
		{input: "did:uport:", error: true},
		{input: "did:uport:1234_12313***", error: true},
		{input: "2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX", error: true},
		{input: "did:method:%12%1", error: true},
		{input: "did:method:%1233%Ay", error: true},
		{input: "did:CAP:id", error: true},
		{input: "did:method:id::anotherid%r9", error: true},
		{
			input: "did:example:123456789abcdefghi",
			output: map[string]interface{}{
				"method": "example",
				"id":     "123456789abcdefghi",
			},
		},
		{
			input: "did:example:123456789abcdefghi;foo=bar;baz=qux",
			output: map[string]interface{}{
				"method": "example",
				"id":     "123456789abcdefghi",
				"params": map[string]string{
					"foo": "bar",
					"baz": "qux",
				},
			},
		},
		{
			input: "did:example:123456789abcdefghi?foo=bar&baz=qux",
			output: map[string]interface{}{
				"method": "example",
				"id":     "123456789abcdefghi",
				"query":  "foo=bar&baz=qux",
			},
		},
		{
			input: "did:example:123456789abcdefghi#keys-1",
			output: map[string]interface{}{
				"method":   "example",
				"id":       "123456789abcdefghi",
				"fragment": "keys-1",
			},
		},
		{
			input: "did:example:123456789abcdefghi?foo=bar&baz=qux#keys-1",
			output: map[string]interface{}{
				"method":   "example",
				"id":       "123456789abcdefghi",
				"query":    "foo=bar&baz=qux",
				"fragment": "keys-1",
			},
		},
		{
			input: "did:example:123456789abcdefghi;foo=bar;baz=qux?foo=bar&baz=qux#keys-1",
			output: map[string]interface{}{
				"method":   "example",
				"id":       "123456789abcdefghi",
				"params":   map[string]string{"foo": "bar", "baz": "qux"},
				"query":    "foo=bar&baz=qux",
				"fragment": "keys-1",
			},
		},
	}

	for _, v := range vectors {
		did, err := did.Parse(v.input)

		if v.error && err == nil {
			t.Errorf("expected error, got nil")
		}

		if err != nil {
			if !v.error {
				t.Errorf("failed to parse did: %s", err.Error())
			}
			continue
		}

		assert.Equal[interface{}](t, v.output["method"], did.Method)
		assert.Equal[interface{}](t, v.output["id"], did.ID)

		if v.output["params"] != nil {
			params, ok := v.output["params"].(map[string]string)
			assert.True(t, ok, "expected params to be map[string]string")

			for k, v := range params {
				assert.Equal[interface{}](t, v, did.Params[k])
			}
		}

		if v.output["query"] != nil {
			assert.Equal[interface{}](t, v.output["query"], did.Query)
		}

		if v.output["fragment"] != nil {
			assert.Equal[interface{}](t, v.output["fragment"], did.Fragment)
		}
	}
}

func TestDID_ScanValueRoundtrip(t *testing.T) {
	tests := []struct {
		object  did.DID
		raw     string
		wantErr bool
	}{
		{
			raw:    "did:example:123456789abcdefghi",
			object: MustParse("did:example:123456789abcdefghi"),
		},
		{
			raw:    "did:example:123456789abcdefghi;foo=bar;baz=qux",
			object: MustParse("did:example:123456789abcdefghi;foo=bar;baz=qux"),
		},
		{
			raw:    "did:example:123456789abcdefghi?foo=bar&baz=qux",
			object: MustParse("did:example:123456789abcdefghi?foo=bar&baz=qux"),
		},
		{
			raw:    "did:example:123456789abcdefghi#keys-1",
			object: MustParse("did:example:123456789abcdefghi#keys-1"),
		},
		{
			raw:    "did:example:123456789abcdefghi?foo=bar&baz=qux#keys-1",
			object: MustParse("did:example:123456789abcdefghi?foo=bar&baz=qux#keys-1"),
		},
		{
			raw:    "did:example:123456789abcdefghi;foo=bar;baz=qux?foo=bar&baz=qux#keys-1",
			object: MustParse("did:example:123456789abcdefghi;foo=bar;baz=qux?foo=bar&baz=qux#keys-1"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			var d did.DID
			if err := d.Scan(tt.raw); (err != nil) != tt.wantErr {
				t.Errorf("Scan() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.object, d)

			value, err := d.Value()
			assert.NoError(t, err)
			assert.Equal(t, tt.raw, value.(string))
		})
	}
}

func MustParse(input string) did.DID {
	d, err := did.Parse(input)
	if err != nil {
		panic(err)
	}
	return d
}
