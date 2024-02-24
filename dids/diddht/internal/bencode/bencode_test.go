package bencode_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/diddht/internal/bencode"
)

func TestMarshal_String(t *testing.T) {
	type vector struct {
		input    string
		expected []byte
	}

	vectors := []vector{
		{"spam", []byte("4:spam")},
		{"", []byte("0:")},
	}

	for _, v := range vectors {
		actual, err := bencode.Marshal(v.input)
		assert.NoError(t, err)

		assert.Equal(t, v.expected, actual)
	}
}

func TestMarshal_Int(t *testing.T) {
	type vector struct {
		input    int
		expected []byte
	}

	vectors := []vector{
		{42, []byte("i42e")},
		{0, []byte("i0e")},
	}

	for _, v := range vectors {
		actual, err := bencode.Marshal(v.input)
		assert.NoError(t, err)

		assert.Equal(t, v.expected, actual)
	}
}

func TestMarshal_List(t *testing.T) {
	input := []any{"spam", "eggs"}
	expected := []byte("l4:spam4:eggse")

	actual, err := bencode.Marshal(input)
	assert.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestMarshal_Dict(t *testing.T) {
	input := map[string]any{
		"spam": []any{"a", "b"},
	}

	expected := []byte("d4:spaml1:a1:bee")

	actual, err := bencode.Marshal(input)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestUnmarshal_String(t *testing.T) {
	input := []byte("4:spam")
	var output string

	err := bencode.Unmarshal(input, &output)
	assert.NoError(t, err)
	assert.Equal(t, "spam", output)
}

func TestUnmarshal_Int(t *testing.T) {
	input := []byte("i42e")
	var output int

	err := bencode.Unmarshal(input, &output)
	assert.NoError(t, err)
	assert.Equal(t, 42, output)
}

func TestUnmarshal_List(t *testing.T) {
	type vector struct {
		input    []byte
		expected []any
	}

	vectors := []vector{
		{
			input:    []byte("l4:spam4:eggse"),
			expected: []any{"spam", "eggs"},
		},
		{
			input:    []byte("le"),
			expected: []any{},
		},
	}

	for _, v := range vectors {
		output := make([]any, 0)
		err := bencode.Unmarshal(v.input, &output)

		assert.NoError(t, err)
		assert.Equal(t, len(v.expected), len(output))

		for i, expected := range v.expected {
			assert.Equal(t, expected, output[i])
		}
	}

}

func TestUnmarshal_Dict(t *testing.T) {

	type vector struct {
		input    []byte
		expected map[string]any
	}

	vectors := []vector{
		{
			input: []byte("d9:publisher3:bob17:publisher-webpage15:www.example.com18:publisher.location4:homee"),
			expected: map[string]any{
				"publisher":          "bob",
				"publisher-webpage":  "www.example.com",
				"publisher.location": "home",
			},
		},
		{
			input: []byte("d3:cow3:moo4:spam4:eggse"),
			expected: map[string]any{
				"cow":  "moo",
				"spam": "eggs",
			},
		},
		{
			input:    []byte("de"),
			expected: map[string]any{},
		},
	}

	for _, v := range vectors {
		output := make(map[string]any)
		err := bencode.Unmarshal(v.input, &output)
		assert.NoError(t, err)
		assert.Equal(t, len(v.expected), len(output))

		for k, expected := range v.expected {
			assert.Equal(t, expected, output[k])
		}
	}
}
