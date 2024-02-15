package bencode

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

const (
	DictionaryPrefix = 'd'
	IntegerPrefix    = 'i'
	ListPrefix       = 'l'
	EndSuffix        = 'e'
)

// Marshal encodes the given input into a Bencode formatted byte array.
// Note: Does not support encoding structs at the moment.
// More information about Bencode can be found at:
// https://wiki.theory.org/BitTorrentSpecification#Bencoding
func Marshal(input any) ([]byte, error) {
	switch v := input.(type) {
	case string:
		encoded := fmt.Sprintf("%d:%s", len(v), v)

		return []byte(encoded), nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		encoded := fmt.Sprintf("%c%d%c", IntegerPrefix, v, EndSuffix)

		return []byte(encoded), nil
	case []byte:
		size := fmt.Sprintf("%d:", len(v))
		encoded := append([]byte(size), v...)

		return encoded, nil
	case []any:
		var b []byte
		b = append(b, ListPrefix)

		for _, item := range v {
			encoded, err := Marshal(item)
			if err != nil {
				return nil, err
			}

			b = append(b, encoded...)
		}

		b = append(b, 'e')

		return b, nil
	case map[string]any:
		var b []byte
		b = append(b, 'd')

		for key, value := range v {
			encodedKey, err := Marshal(key)
			if err != nil {
				return nil, err
			}

			encodedValue, err := Marshal(value)
			if err != nil {
				return nil, err
			}

			b = append(b, encodedKey...)
			b = append(b, encodedValue...)
		}

		b = append(b, 'e')

		return b, nil
	default:
		return nil, fmt.Errorf("unsupported type: %T", input)
	}
}

// Unmarshal decodes a Bencode formatted byte array into the the type of the provided output.
// More information can be found at:
// https://wiki.theory.org/BitTorrentSpecification#Bencoding
func Unmarshal(input []byte, output any) error {
	switch v := output.(type) {
	case *string:
		_, err := unmarshalString(input, v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal string: %w", err)
		}
	case *int:
		_, err := unmarshalInt(input, v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal int: %w", err)
		}
	case *[]any:
		_, err := unmarshalList(input, v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal list: %w", err)
		}
	case *map[string]any:
		_, err := unmarshalDict(input, *v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal dict: %w", err)
		}
	default:
		return fmt.Errorf("unsupported type: %T", output)
	}

	return nil
}

// unmarshalValue decodes a Bencode value from a byte slice and returns
// the decoded value, the # of bytes processed, and an error if any.
func unmarshalValue(input []byte) (any, int, error) {
	switch input[0] {
	case IntegerPrefix:
		var value int
		n, err := unmarshalInt(input, &value)
		if err != nil {
			return nil, 0, err
		}

		return value, n, nil
	case ListPrefix:
		value := make([]any, 0)
		n, err := unmarshalList(input, &value)
		if err != nil {
			return nil, 0, err
		}

		return value, n, nil
	case DictionaryPrefix:
		value := make(map[string]any)
		n, err := unmarshalDict(input, value)
		if err != nil {
			return nil, 0, err
		}

		return value, n, nil
	default:
		var value string
		n, err := unmarshalString(input, &value)
		if err != nil {
			return nil, 0, err
		}

		return value, n, nil
	}
}

// unmarshalString decodes a Bencode string from a byte slice.
// It returns the total bytes processed, and an error if any.
func unmarshalString(input []byte, output *string) (int, error) {
	// Find the colon index, which separates the length part from the data part.
	colonIndex := bytes.IndexByte(input, ':')
	if colonIndex == -1 {
		return 0, errors.New("colon not found in input")
	}

	// Extract the length part and convert it to an integer.
	lengthPart := input[:colonIndex]
	length, err := strconv.Atoi(string(lengthPart))
	if err != nil {
		return 0, fmt.Errorf("failed to convert length: %w", err)
	}

	// Calculate the start and end of the actual string data.
	start := colonIndex + 1
	end := start + length

	// Check if the calculated end exceeds the input length.
	if end > len(input) {
		return 0, errors.New("data length exceeds input length")
	}

	// Extract and return the actual string data.
	*output = string(input[start:end])
	return end, nil // end is the total bytes processed.
}

// unmarshalInt decodes a Bencode integer from a byte slice.
// It returns the total bytes processed, and an error if any.
func unmarshalInt(input []byte, output *int) (int, error) {
	if input[0] != IntegerPrefix {
		return 0, fmt.Errorf("input does not start with %q", IntegerPrefix)
	}

	// Find the suffix byte which marks the end of the integer.
	endIndex := bytes.IndexByte(input, EndSuffix)
	if endIndex == -1 {
		return 0, errors.New("end byte not found in input")
	}

	// Extract the data between prefix and suffix bytes and convert it to an integer.
	intPart := input[1:endIndex]
	str := string(intPart)
	value, err := strconv.Atoi(str)
	if err != nil {
		return 0, fmt.Errorf("failed to convert %s into int: %w", str, err)
	}

	// Assign the decoded integer to the output.
	*output = value
	return endIndex + 1, nil // endIndex + 1 is the total bytes processed.
}

// unmarshalList decodes a Bencode list from a byte slice.
// It returns the total bytes processed, and an error if any.
func unmarshalList(input []byte, output *[]any) (int, error) {
	// Iterate over the input bytes and decode each list item.
	i := 1 // Skip the prefix byte.
	for i < len(input) {
		// Check if we have reached the end of the list.
		if input[i] == EndSuffix {
			return i + 1, nil // i + 1 is the total bytes processed.
		}

		value, n, err := unmarshalValue(input[i:])
		if err != nil {
			return 0, fmt.Errorf("failed to decode list item: %w", err)
		}

		*output = append(*output, value)
		i += n
	}

	return i, errors.New("unexpected end of input")
}

// unmarshalDict decodes a Bencode dictionary from a byte slice.
// It returns the total bytes processed, and an error if any.
func unmarshalDict(input []byte, output map[string]any) (int, error) {
	if input[0] != DictionaryPrefix {
		return 0, errors.New("input does not start with 'd'")
	}

	// Iterate over the input bytes and decode each key-value pair.
	i := 1 // Skip the prefix byte.
	for i < len(input) {
		// Check if we have reached the end of the dictionary.
		if input[i] == EndSuffix {
			return i + 1, nil // i + 1 is the total bytes processed.
		}

		// Decode the key.
		var key string
		n, err := unmarshalString(input[i:], &key)
		if err != nil {
			return 0, fmt.Errorf("failed to decode key: %w", err)
		}
		i += n

		value, n, err := unmarshalValue(input[i:])
		if err != nil {
			return 0, fmt.Errorf("failed to decode value: %w", err)
		}

		output[key] = value
		i += n
	}

	return i, errors.New("unexpected end of input")
}
