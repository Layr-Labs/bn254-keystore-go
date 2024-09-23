package mnemonic

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testVectorFilePath = filepath.Join(os.Getenv("PWD"), "..", "tests_vectors", "tree_kdf_intermediate.json")
	testVector         struct {
		Mnemonic            string   `json:"mnemonic"`
		Password            string   `json:"password"`
		Seed                string   `json:"seed"`
		MasterSK            *big.Int `json:"master_SK"`
		Path                string   `json:"path"`
		ChildIndex          uint32   `json:"child_index"`
		Lamport0            []string `json:"lamport_0"`
		Lamport1            []string `json:"lamport_1"`
		CompressedLamportPK string   `json:"compressed_lamport_PK"`
		ChildSK             *big.Int `json:"child_SK"`
	}
)

func init() {
	// Load test vectors from the JSON file
	data, err := ioutil.ReadFile(testVectorFilePath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load test vectors: %v", err))
	}

	err = json.Unmarshal(data, &testVector)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse test vectors: %v", err))
	}
}

// TestFlipBits256 tests the flipBits256 function.
func TestFlipBits256(t *testing.T) {
	// Retrieve the test vector (assumed to be defined elsewhere)

	// Extract the first 64 characters of the seed hex string
	seedHex := testVector.Seed
	if len(seedHex) < 64 {
		t.Fatalf("Seed hex string is less than 64 characters")
	}
	seedHex = seedHex[:64]

	// Convert the hex string to a big.Int
	testVectorInt := new(big.Int)
	_, ok := testVectorInt.SetString(seedHex, 16)
	if !ok {
		t.Fatalf("Failed to parse seed hex string")
	}

	// Flip the bits of the integer
	flippedBits := FlipBits256(testVectorInt)

	// Compute testVectorInt & flippedBits
	andResult := new(big.Int).And(testVectorInt, flippedBits)

	// Check that the result is zero
	if andResult.Sign() != 0 {
		t.Errorf("testVectorInt & flipBits256(testVectorInt) != 0")
	}
}

// TestIKMToLamportSK tests the IKMToLamportSK function.
func TestIKMToLamportSK(t *testing.T) {

	// Convert test_vector['lamport_0'] and ['lamport_1'] from hex strings to [][]byte
	lamport0HexStrings := testVector.Lamport0
	testVectorLamport0 := make([][]byte, len(lamport0HexStrings))
	for i, hexStr := range lamport0HexStrings {
		theBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Fatalf("Failed to decode lamport_0 hex string at index %d: %v", i, err)
		}
		testVectorLamport0[i] = theBytes
	}

	lamport1HexStrings := testVector.Lamport1
	testVectorLamport1 := make([][]byte, len(lamport1HexStrings))
	for i, hexStr := range lamport1HexStrings {
		theBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Fatalf("Failed to decode lamport_1 hex string at index %d: %v", i, err)
		}
		testVectorLamport1[i] = theBytes
	}

	// Get salt: test_vector['child_index'] converted to 4-byte big-endian bytes
	childIndex := testVector.ChildIndex
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, childIndex)

	// Get IKM: test_vector['master_SK'] converted to 32-byte big-endian bytes
	masterSK := testVector.MasterSK
	IKM := masterSK.Bytes()
	// Ensure IKM is 32 bytes
	if len(IKM) < 32 {
		padding := make([]byte, 32-len(IKM))
		IKM = append(padding, IKM...)
	}

	// Compute lamport_0
	lamport0, err := IkmToLamportSK(IKM, salt)
	assert.NoError(t, err)
	// Compute not_IKM by flipping bits of master_SK and converting to 32-byte big-endian bytes
	notMasterSK := FlipBits256(masterSK)
	notIKM := notMasterSK.Bytes()
	// Ensure notIKM is 32 bytes
	if len(notIKM) < 32 {
		padding := make([]byte, 32-len(notIKM))
		notIKM = append(padding, notIKM...)
	}

	// Compute lamport_1
	lamport1, err := IkmToLamportSK(notIKM, salt)
	assert.NoError(t, err)

	// Assert test_vector_lamport_0 == lamport0
	if len(testVectorLamport0) != len(lamport0) {
		t.Errorf("lamport_0 length mismatch: expected %d, got %d", len(testVectorLamport0), len(lamport0))
	} else {
		for i := range testVectorLamport0 {
			if !bytes.Equal(testVectorLamport0[i], lamport0[i]) {
				t.Errorf("lamport_0 mismatch at index %d", i)
			}
		}
	}

	// Assert test_vector_lamport_1 == lamport1
	if len(testVectorLamport1) != len(lamport1) {
		t.Errorf("lamport_1 length mismatch: expected %d, got %d", len(testVectorLamport1), len(lamport1))
	} else {
		for i := range testVectorLamport1 {
			if !bytes.Equal(testVectorLamport1[i], lamport1[i]) {
				t.Errorf("lamport_1 mismatch at index %d", i)
			}
		}
	}
}

// TestParentSKToLamportPK tests the parentSKToLamportPK function.
func TestParentSKToLamportPK(t *testing.T) {

	// Retrieve the test vector
	parentSK := testVector.MasterSK
	index := testVector.ChildIndex

	// Decode the expected compressed Lamport PK from hex string
	expectedLamportPK, err := hex.DecodeString(testVector.CompressedLamportPK)
	if err != nil {
		t.Fatalf("Failed to decode compressed_lamport_PK hex string: %v", err)
	}

	// Compute the Lamport PK using the parentSKToLamportPK function
	computedLamportPK, err := ParentSKToLamportPK(parentSK, index)
	assert.NoError(t, err)

	// Compare the expected and computed Lamport PKs
	assert.Equal(t, expectedLamportPK, computedLamportPK)
}

// hexDecodeOrFail decodes a hex string or fails the test.
func hexDecodeOrFail(t *testing.T, s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}
	return data
}

// TestHKDFModR tests the HKDFModR function.
func TestHKDFModR(t *testing.T) {

	// Prepare test cases
	tests := []struct {
		IKM      []byte
		Expected *big.Int
	}{
		{
			IKM:      hexDecodeOrFail(t, testVector.Seed),
			Expected: testVector.MasterSK,
		},
		{
			IKM:      hexDecodeOrFail(t, testVector.CompressedLamportPK),
			Expected: testVector.ChildSK,
		},
	}

	for _, test := range tests {
		result, err := HKDFModR(test.IKM, []byte(""))
		if err != nil {
			t.Fatalf("Failed to derive secret key: %v", err)
		}

		if result.Cmp(test.Expected) != 0 {
			t.Errorf("HKDFModR(%x) = %s, expected %s", test.IKM, result.String(), test.Expected.String())
		}
	}
}

// TestMnemonicAndPathToKey tests the MnemonicAndPathToKey function.
func TestMnemonicAndPathToKey(t *testing.T) {

	mnemonic := testVector.Mnemonic
	password := testVector.Password
	path := testVector.Path
	expectedKey := testVector.ChildSK

	// Call MnemonicAndPathToKey
	derivedKey, err := MnemonicAndPathToKey(mnemonic, password, path)
	if err != nil {
		t.Fatalf("MnemonicAndPathToKey returned an error: %v", err)
	}

	// Compare the derived key with the expected key
	if derivedKey.Cmp(expectedKey) != 0 {
		t.Errorf(
			"Derived key does not match expected value.\nExpected: %s\nGot:      %s",
			expectedKey.String(),
			derivedKey.String(),
		)
	}
}

// TestPathToNodes tests the pathToNodes function with various paths to verify correct parsing and error handling.
func TestPathToNodes(t *testing.T) {
	tests := []struct {
		path  string
		valid bool
	}{
		{"m/12381/3600/0/0/0", true},
		{"x/12381/3600/0/0/0", false},
		{"m/qwert/3600/0/0/0", false},
	}

	for _, test := range tests {
		_, err := pathToNodes(test.path)
		if test.valid {
			if err != nil {
				t.Errorf("Expected pathToNodes(%q) to succeed, but got error: %v", test.path, err)
			}
		} else {
			if err == nil {
				t.Errorf("Expected pathToNodes(%q) to fail, but got no error", test.path)
			}
		}
	}
}
