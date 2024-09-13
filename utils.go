package bls_keystore_bn254_go

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// getKeyFromMap is a helper function that tries to get a key from a map and returns an error if the key is not found
func getKeyFromMap(data map[string]interface{}, key string) (interface{}, error) {
	value, exists := data[key]
	if !exists {
		return nil, fmt.Errorf("key '%s' not found in map", key)
	}
	return value, nil
}

// generateRandomBytes generates n random bytes
func generateRandomBytes(n int) []byte {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("failed to generate random bytes")
	}
	return bytes
}

// generateUUID generates a random UUID for the keystore
func generateUUID() string {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		panic("failed to generate UUID")
	}

	// Set variant and version bits
	uuid[8] = uuid[8]&^0xc0 | 0x80
	uuid[6] = uuid[6]&^0xf0 | 0x40

	return hex.EncodeToString(uuid)
}
