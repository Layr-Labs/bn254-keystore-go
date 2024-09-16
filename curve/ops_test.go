package curve

import (
	"encoding/hex"
	"testing"

	bls12381Fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254Fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestCurveOps(t *testing.T) {
	tests := []struct {
		curveName string
		secret    []byte
		valid     bool
	}{
		{curveName: "bls12-381", secret: []byte{0x01, 0x02, 0x03, 0x04}, valid: true},
		{curveName: "bn254", secret: []byte{0x05, 0x06, 0x07, 0x08}, valid: true},
		{curveName: "unsupported-curve", secret: []byte{0x09, 0x0A, 0x0B, 0x0C}, valid: false},
	}

	for _, test := range tests {
		ops, exists := OpsMap[test.curveName]
		if !exists {
			if test.valid {
				t.Errorf("Expected curve '%s' to be supported", test.curveName)
			}
			continue
		}

		publicKeyBytes := ops.GenerateG2PubKey(test.secret)
		assert.NotNil(t, publicKeyBytes)
		assert.NotEmpty(t, publicKeyBytes)
	}
}

func TestSetBytes(t *testing.T) {
	tests := []struct {
		curveName string
		secret    []byte
		expected  interface{}
	}{
		{curveName: "bls12-381", secret: []byte{0x01, 0x02, 0x03, 0x04}, expected: bls12381Fr.Element{}},
		{curveName: "bn254", secret: []byte{0x05, 0x06, 0x07, 0x08}, expected: bn254Fr.Element{}},
	}

	for _, test := range tests {
		ops, exists := OpsMap[test.curveName]
		if !exists {
			t.Errorf("Curve '%s' not supported", test.curveName)
			continue
		}

		if test.curveName == "bls12-381" {
			publicKeyBytes := ops.GenerateG2PubKey(test.secret)
			publicKeyFr := bls12381Fr.Element{}
			decodedHex, _ := hex.DecodeString(publicKeyBytes)
			publicKeyFr.SetBytes(decodedHex)
			assert.IsType(t, test.expected, publicKeyFr)
		} else if test.curveName == "bn254" {
			publicKeyBytes := ops.GenerateG2PubKey(test.secret)
			publicKeyFr := bn254Fr.Element{}
			decodedHex, _ := hex.DecodeString(publicKeyBytes)
			publicKeyFr.SetBytes(decodedHex)
			assert.IsType(t, test.expected, publicKeyFr)
		}
	}
}
