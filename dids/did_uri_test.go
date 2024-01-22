package dids_test

import (
	"testing"

	"github.com/tbd54566975/web5-go/dids"
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
		did, err := dids.ParseURI(v.input)

		if v.error && err == nil {
			t.Errorf("expected error, got nil")
		}

		if err != nil {
			if !v.error {
				t.Errorf("failed to parse did: %s", err.Error())
			}
			continue
		}

		if did.Method != v.output["method"] {
			t.Errorf("expected method %s, got %s", v.output["method"], did.Method)
		}

		if did.ID != v.output["id"] {
			t.Errorf("expected id %s, got %s", v.output["id"], did.ID)
		}

		if v.output["params"] != nil {
			params, ok := v.output["params"].(map[string]string)
			if !ok {
				t.Errorf("failed to assert params as map[string]string")
				continue
			}
			for k, v := range params {
				if did.Params[k] != v {
					t.Errorf("expected param %s to be %s, got %s", k, v, did.Params[k])
				}
			}
		}

		if v.output["query"] != nil {
			if did.Query != v.output["query"] {
				t.Errorf("expected query %s, got %s", v.output["query"], did.Query)
			}
		}

		if v.output["fragment"] != nil {
			if did.Fragment != v.output["fragment"] {
				t.Errorf("expected fragment %s, got %s", v.output["fragment"], did.Fragment)
			}
		}
	}
}
