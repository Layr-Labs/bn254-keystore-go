package keystore

import (
	curve2 "bn254-keystore-go/curve"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// generateRandomBytes generates a slice of cryptographically secure random bytes of the specified length.
//
// Parameters:
//   - n (int): The number of random bytes to generate.
//
// Returns:
//   - []byte: A byte slice containing `n` cryptographically secure random bytes.
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

// GetKeyFromMap is a helper function that tries to get a key from a map and returns an error if the key is not found
func GetKeyFromMap(data map[string]interface{}, key string) (interface{}, error) {
	value, exists := data[key]
	if !exists {
		return nil, fmt.Errorf("key '%s' not found in map", key)
	}
	return value, nil
}

// Sha256Hash returns the SHA-256 hash of the input.
//
// Parameters:
//   - input ([]byte): The input byte slice to be hashed.
//
// Returns:
//   - []byte: The resulting SHA-256 hash.
func Sha256Hash(input []byte) []byte {
	hash := sha256.Sum256(input)
	return hash[:]
}

// Equal Utility function to check if two byte slices are equal
func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// BlsSkToPk converts a BLS secret key to a public key.
//
// Parameters:
//   - secret ([]byte): The BLS secret key as a byte slice.
//
// Returns:
//   - string: The BLS public key as a hex-encoded string.
//   - error: An error object if the conversion fails.
func BlsSkToPk(secret []byte, curve string) (string, error) {
	ops, exists := curve2.OpsMap[curve]
	if !exists {
		return "", fmt.Errorf("curve '%s' not supported", curve)
	}
	return ops.GenerateG2PubKey(secret), nil
}
