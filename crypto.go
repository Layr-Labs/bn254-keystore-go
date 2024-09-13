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
	"math/big"
	"strings"
)

// Scrypt key derivation function.
//
// This function derives a key from a password using the Scrypt key derivation algorithm.
//
// This function derives a key from a password using the Scrypt key derivation algorithm.
//
// Parameters:
//   - password: The input password as a byte slice.
//   - salt: The salt to use for key derivation as a byte slice.
//   - n: CPU/memory cost parameter.
//   - r: Block size parameter.
//   - p: Parallelization parameter.
//   - dklen: Desired key length.
//
// Returns:
//   - p: Parallelization parameter.
//   - A derived key as a byte slice.
func Scrypt(password []byte, salt []byte, n, r, p, dklen int) ([]byte, error) {
	// Security check on Scrypt parameters
	if n*r*p < 1<<20 { // 128 MB memory usage
		return nil, errors.New("the Scrypt parameters chosen are not secure")
	}

	maxTerm := new(big.Int).Lsh(big.NewInt(1), uint(128*float64(r)/8))
	bigN := new(big.Int).SetUint64(uint64(n))
	if bigN.Cmp(maxTerm) >= 0 {
		return nil, errors.New(fmt.Sprintf("the given `n`=%d should be less than `%d`", n, maxTerm))
	}
	// Perform Scrypt key derivation
	return scrypt.Key(password, salt, n, r, p, dklen)
}

// PBKDF2 key derivation function.
//
// This function derives a key from a password using the PBKDF2 key derivation algorithm.
//
// Parameters:
// This function derives a key from a password using the PBKDF2 key derivation algorithm.
//
// Parameters:
//   - password: The input password as a byte slice.
//   - salt: The salt to use for key derivation as a byte slice.
//   - dklen: Desired key length.
//   - c: Iteration count.
//   - prf: Pseudorandom function to use (e.g., "sha256" or "sha512").
//
// Returns:
//   - A derived key as a byte slice.
//   - prf: Pseudorandom function to use (e.g., "sha256" or "sha512").
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

// Aes128CTREncrypt encrypts the given plaintext using AES-128 in CTR mode.
// Parameters:
//   - key: The encryption key as a byte slice (must be 16 bytes long).
//   - iv: The initialization vector as a byte slice.
//   - plaintext: The plaintext to encrypt as a byte slice.
//
// Returns:
//   - The encrypted ciphertext as a byte slice.
//   - plaintext: The plaintext to encrypt as a byte slice.
func Aes128CTREncrypt(key, iv, plaintext []byte) ([]byte, error) {

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

// Aes128CTRDecrypt decrypts a ciphertext using AES-128 in CTR (Counter) mode.
//
// It uses the provided key and initialization vector (IV) to decrypt the ciphertext and return the plaintext.
// The IV is obtained by calling `ks.Crypto.IV()`. Note that the `params` parameter is currently not used in this function.
//
// Parameters:
//   - key: A byte slice containing the decryption key.
//   - Must be exactly 16 bytes long to match the AES-128 specification.
//   - ciphertext: A byte slice containing the data to be decrypted.
//   - params: A map containing cipher parameters.
//   - **Currently unused** in this function.
//   - Intended to hold cipher parameters like the IV.
//
// Returns:
//   - A byte slice containing the decrypted plaintext.
//   - An error if the decryption fails.
func (ks *Keystore) Aes128CTRDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv, err := ks.Crypto.IV() // Get the IV from the cipher params
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV size: %d", len(iv))
	}

	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
