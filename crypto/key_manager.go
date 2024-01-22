package crypto

import (
	"fmt"

	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/jwk"
)

// KeyManager is an abstraction that can be leveraged to manage/use keys (create, sign etc) as desired per the given use case
// examples of concrete implementations include: AWS KMS, Azure Key Vault, Google Cloud KMS, Hashicorp Vault etc
type KeyManager interface {
	// GeneratePrivateKey generates a new private key, stores it in the key store and returns the key id
	GeneratePrivateKey(algorithmID string) (string, error)

	// GetPublicKey returns the public key for the given key id
	GetPublicKey(keyID string) (jwk.JWK, error)

	// Sign signs the given payload with the private key for the given key id
	Sign(keyID string, payload []byte) ([]byte, error)
}

// InMemoryKeyManager is an implementation of KeyManager that stores keys in memory
type InMemoryKeyManager struct {
	keys map[string]jwk.JWK
}

// NewInMemoryKeyManager returns a new instance of InMemoryKeyManager
func NewInMemoryKeyManager() *InMemoryKeyManager {
	return &InMemoryKeyManager{
		keys: make(map[string]jwk.JWK),
	}
}

// GeneratePrivateKey generates a new private key using the algorithm provided,
// stores it in the key store and returns the key id
// Supported algorithms are available in [github.com/tbd54566975/web5-go/crypto/dsa.AlgorithmID]
func (k *InMemoryKeyManager) GeneratePrivateKey(algorithmID string) (string, error) {
	var keyAlias string

	key, err := dsa.GeneratePrivateKey(algorithmID)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	keyAlias, err = key.ComputeThumbprint()
	if err != nil {
		return "", fmt.Errorf("failed to compute key alias: %w", err)
	}

	k.keys[keyAlias] = key

	return keyAlias, nil
}

// GetPublicKey returns the public key for the given key id
func (k *InMemoryKeyManager) GetPublicKey(keyID string) (jwk.JWK, error) {
	key, err := k.getPrivateJWK(keyID)
	if err != nil {
		return jwk.JWK{}, err
	}

	return dsa.GetPublicKey(key), nil

}

// Sign signs the payload with the private key for the given key id
func (k *InMemoryKeyManager) Sign(keyID string, payload []byte) ([]byte, error) {
	key, err := k.getPrivateJWK(keyID)
	if err != nil {
		return nil, err
	}

	return dsa.Sign(payload, key)
}

func (k *InMemoryKeyManager) getPrivateJWK(keyID string) (jwk.JWK, error) {
	key, ok := k.keys[keyID]

	if !ok {
		return jwk.JWK{}, fmt.Errorf("key with alias %s not found", keyID)
	}

	return key, nil
}
