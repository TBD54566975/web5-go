package crypto

import "github.com/google/uuid"

func RandomUUID() string {
	return uuid.New().String()
}
