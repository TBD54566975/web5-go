package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

func GenerateEntropy(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("entropy byte size must be > 0")
	}

	bytes := make([]byte, n)
	size, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	if size != n {
		return nil, errors.New("random generation failed to match expected size")
	}

	return bytes, nil
}

func GenerateHexNonce() (string, error) {
	// 16 bytes was chosen because 16 bytes = 128 bits which is considered minimally sufficient
	//		https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
	bytes, err := GenerateEntropy(16)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
