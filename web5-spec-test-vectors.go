package web5go

import (
	"encoding/json"
	"os"
)

// TestVectors are JSON files which are tested against to ensure interop with the specification
type TestVectors[T, U any] struct {
	Description string             `json:"description"`
	Vectors     []TestVector[T, U] `json:"vectors"`
}

// TestVector is an individual test vector case
type TestVector[T, U any] struct {
	Description string `json:"description"`
	Input       T      `json:"input"`
	Output      U      `json:"output"`
	Errors      bool   `json:"errors"`
}

// ReadTestVector is for reading the vector at the given path
func ReadTestVector[T, U any](path string) (TestVectors[T, U], error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TestVectors[T, U]{}, err
	}

	var testVectors TestVectors[T, U]
	err = json.Unmarshal(data, &testVectors)
	if err != nil {
		return TestVectors[T, U]{}, err
	}

	return testVectors, nil
}
