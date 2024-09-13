package bls_keystore_bn254_go

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"hash"
	"math"
	"strings"
)

// Scrypt key derivation function.
func Scrypt(password []byte, salt []byte, n, r, p, dklen int) ([]byte, error) {
	// Security check on Scrypt parameters
	if n*r*p < 1<<20 { // 128 MB memory usage
		return nil, errors.New("the Scrypt parameters chosen are not secure")
	}
	if n >= int(math.Pow(2, 128*float64(r)/8)) {
		return nil, errors.New("the given `n` should be less than `2**(128 * r / 8)`")
	}
	// Perform Scrypt key derivation
	return scrypt.Key(password, salt, n, r, p, dklen)
}

// PBKDF2 key derivation function.
func PBKDF2(password, salt []byte, dklen, c int, prf string) ([]byte, error) {
	var hashFunc func() hash.Hash

	// Choose hash function based on prf
	switch {
	case strings.Contains(prf, "sha256"):
		if c < 1<<18 {
			return nil, errors.New("the PBKDF2 parameters chosen are not secure")
		}
		hashFunc = sha256.New
	case strings.Contains(prf, "sha512"):
		hashFunc = sha512.New
	default:
		return nil, errors.New("unsupported PRF, expected `sha256` or `sha512`")
	}

	// Perform PBKDF2 key derivation
	return pbkdf2.Key(password, salt, c, dklen, hashFunc), nil
}

// AES128CTR encrypts the secret using AES-128-CTR
func AES128CTR(key, iv, plaintext []byte) ([]byte, error) {

	if len(key) != 16 {
		return nil, errors.New("key length should be 16 bytes")
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}
