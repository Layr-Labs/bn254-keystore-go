package bls_keystore_bn254_go

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"golang.org/x/crypto/hkdf"
	"io"
	"math"
	"math/big"
)

var blsCurveOrder = fr.Modulus()

// flipBits256 flips 256 bits of the given input
func flipBits256(input *big.Int) *big.Int {
	maxVal := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256
	maxVal.Sub(maxVal, big.NewInt(1))              // 2^256 - 1
	return new(big.Int).Xor(input, maxVal)
}

// IkmToLamportSK derives the lamport SK for a given IKM and salt using HKDF.
func IkmToLamportSK(IKM, salt []byte) ([][]byte, error) {
	OKM, err := hkdfExpand(salt, IKM, 8160)
	if err != nil {
		return nil, err
	}
	var lamportSK [][]byte
	for i := 0; i < 8160; i += 32 {
		lamportSK = append(lamportSK, OKM[i:i+32])
	}
	return lamportSK, nil
}

// hkdfExpand simulates HKDF-Expand for key derivation using standard Go HKDF and SHA256
func hkdfExpand(salt, ikm []byte, length int) ([]byte, error) {
	hashFunc := sha256.New
	hkdfReader := hkdf.New(hashFunc, ikm, salt, nil)
	output := make([]byte, length)
	_, err := io.ReadFull(hkdfReader, output)
	if err != nil {
		return nil, err // handle error properly in real implementation
	}
	return output, nil
}

// parentSKToLamportPK derives the `index`th child's lamport PK from the `parent_SK`.
func parentSKToLamportPK(parentSK *big.Int, index uint32) ([]byte, error) {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, index)

	IKM := parentSK.Bytes()
	lamport0, err := IkmToLamportSK(IKM, salt)
	if err != nil {
		return nil, err
	}
	notIKM := flipBits256(parentSK).Bytes()
	lamport1, err := IkmToLamportSK(notIKM, salt)
	if err != nil {
		return nil, err
	}
	lamportSKs := append(lamport0, lamport1...)
	var lamportPKs [][]byte
	for _, sk := range lamportSKs {
		lamportPKs = append(lamportPKs, sha256Hash(sk))
	}

	compressedPK := sha256Hash(bytes.Join(lamportPKs, nil))
	return compressedPK, nil
}

// sha256Hash returns the SHA-256 hash of the input
func sha256Hash(input []byte) []byte {
	hash := sha256.Sum256(input)
	return hash[:]
}

// HKDFModR implements the HKDF_mod_r function as specified in EIP-2333.
// It derives a secret key modulo the BLS curve order from the input key material (IKM).
func hKDFModR(IKM []byte, keyInfo []byte) (*big.Int, error) {
	// L is the output length in bytes.
	L := 48 // ceil((3 * ceil(log2(r))) / 16), where r is the order of the BLS12-381 curve

	// Initialize salt to 'BLS-SIG-KEYGEN-SALT-'
	salt := []byte("BLS-SIG-KEYGEN-SALT-")
	SK := new(big.Int)
	zero := new(big.Int)

	for SK.Cmp(zero) == 0 {
		salt = sha256Hash(salt)

		// Append 0x00 to IKM
		ikm := append(IKM, 0x00)

		// Prepare info = keyInfo + L encoded as a 2-byte big-endian integer
		info := append(keyInfo, byte(L>>8), byte(L&0xff))

		// Initialize HKDF with SHA256, salt, IKM, and info
		hkdfReader := hkdf.New(sha256.New, ikm, salt, info)

		// Read L bytes from HKDF output
		okm := make([]byte, L)
		n, err := io.ReadFull(hkdfReader, okm)
		if err != nil {
			return nil, fmt.Errorf("HKDF error: %v", err)
		}
		if n != L {
			return nil, fmt.Errorf("HKDF output length is incorrect: expected %d bytes, got %d bytes", L, n)
		}

		SK.SetBytes(okm)
		SK.Mod(SK, blsCurveOrder)
	}

	return SK, nil
}

// deriveChildSK derives the child SK at the supplied `index` from the parent SK.
func deriveChildSK(parentSK *big.Int, index uint32) (*big.Int, error) {
	if index < 0 || uint64(index) >= uint64(math.Pow(2, 32)) {
		return nil, errors.New("`index` should be greater than or equal to 0 and less than 2^32")
	}
	lamportPK, err := parentSKToLamportPK(parentSK, index)
	if err != nil {
		return nil, err
	}
	return hKDFModR(lamportPK, []byte(""))
}

// deriveMasterSK derives the master SK from a seed.
func deriveMasterSK(seed []byte) (*big.Int, error) {
	if len(seed) < 32 {
		return nil, errors.New("`len(seed)` should be greater than or equal to 32")
	}
	return hKDFModR(seed, []byte(""))
}
