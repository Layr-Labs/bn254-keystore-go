package keystore

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScryptInvalidParams(t *testing.T) {
	tests := []struct {
		N     int
		r     int
		p     int
		valid bool
	}{
		// Valid parameters
		{N: 131072, r: 8, p: 1, valid: true},
		// Unsafe parameters (might cause excessive resource consumption)
		{N: 65536, r: 8, p: 1, valid: false},
		// Invalid N (must be > 1 and a power of two)
		{N: 10000, r: 8, p: 1, valid: false},
		// Invalid r (must be > 0)
		{N: 16384, r: 0, p: 1, valid: false},
		// Invalid p (must be > 0)
		{N: 16384, r: 8, p: 0, valid: false},
		// N not a power of two
		{N: 5000, r: 8, p: 1, valid: false},
		// N <= 1
		{N: 1, r: 8, p: 1, valid: false},
		// Negative N
		{N: -16384, r: 8, p: 1, valid: false},
	}

	for _, test := range tests {
		_, err := Scrypt([]byte("mypassword"), []byte("mysalt"), test.N, test.r, test.p, 32)
		if test.valid {
			if err != nil {
				t.Errorf(
					"Expected scrypt.Key to succeed with n=%d, r=%d, p=%d, but got error: %v",
					test.N,
					test.r,
					test.p,
					err,
				)
			}
		} else {
			if err == nil {
				t.Errorf("Expected scrypt.Key to fail with n=%d, r=%d, p=%d, but got no error", test.N, test.r, test.p)
			}
		}
	}
}

func TestPBKDF2InvalidPRF(t *testing.T) {
	tests := []struct {
		prf   string
		valid bool
	}{
		// Valid PRF using SHA-512
		{prf: "sha512", valid: true},
		// Invalid PRF (simulated by invalidHash)
		{prf: "512", valid: false},
	}

	for _, test := range tests {
		password := []byte("mypassword")
		salt := []byte("mysalt")
		c := 2048
		dklen := 64

		if test.valid {
			// Should succeed without errors
			key, err := PBKDF2(password, salt, dklen, c, test.prf)
			assert.NoError(t, err)
			if len(key) != dklen {
				t.Errorf("Expected key length %d, got %d", dklen, len(key))
			}
		} else {
			// Should fail, expect a panic due to invalid PRF
			_, err := PBKDF2(password, salt, dklen, c, test.prf)
			assert.Error(t, err)
		}
	}
}

func TestPBKDF2InvalidCount(t *testing.T) {
	tests := []struct {
		count int
		prf   string
		valid bool
	}{
		{count: 262144, prf: "sha256", valid: true},
		{count: 131072, prf: "sha256", valid: false},
		{count: 2048, prf: "sha512", valid: true},
	}

	password := []byte("mypassword")
	salt := []byte("mysalt")
	dklen := 64

	for _, test := range tests {

		c := test.count
		if test.valid {
			// Should succeed without errors
			_, err := PBKDF2(password, salt, dklen, c, test.prf)
			assert.NoError(t, err)
		} else {
			// Should fail, expect an error
			_, err := PBKDF2(password, salt, dklen, c, test.prf)
			assert.Error(t, err)
		}
	}
}

// hexDecodeOrFail decodes a hex string or fails the test.
func hexDecodeOrFail(t *testing.T, s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}
	return data
}

func TestAES128CTR(t *testing.T) {
	tests := []struct {
		key   []byte
		iv    []byte
		valid bool
	}{
		{
			key: []byte{
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
			}, // 16 bytes key
			iv: hexDecodeOrFail(
				t,
				"edc2606468f9660ad222690db8836a9d",
			), // 16 bytes IV
			valid: true,
		},
		{
			key: []byte{
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
				0x12,
			}, // 15 bytes key
			iv: hexDecodeOrFail(
				t,
				"edc2606468f9660ad222690db8836a9d",
			), // 16 bytes IV
			valid: false,
		},
	}

	for _, test := range tests {
		_, err := Aes128CTREncrypt(test.key, test.iv, []byte(""))
		if test.valid {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
		}
	}
}
