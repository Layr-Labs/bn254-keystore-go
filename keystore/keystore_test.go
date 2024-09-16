package keystore

import (
	"encoding/hex"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testVectorPassword = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"
var testVectorSecret = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f}
var testVectorFolder = filepath.Join(os.Getenv("PWD"), "..", "tests_vectors", "keystore")

func loadTestVectorFiles() ([]string, error) {
	files, err := ioutil.ReadDir(testVectorFolder)
	if err != nil {
		return nil, err
	}

	var testVectorFiles []string
	for _, file := range files {
		if !file.IsDir() {
			testVectorFiles = append(testVectorFiles, file.Name())
		}
	}
	return testVectorFiles, nil
}

func loadTestVectorKeystores(testVectorFiles []string) ([]*Keystore, error) {
	var testVectorKeystores []*Keystore
	for _, file := range testVectorFiles {
		var ks Keystore
		keystorePath := filepath.Join(testVectorFolder, file)
		err := ks.FromFile(keystorePath)
		if err != nil {
			return nil, err
		}
		testVectorKeystores = append(testVectorKeystores, &ks)
	}
	return testVectorKeystores, nil
}

func TestJsonSerialization(t *testing.T) {
	testVectorFiles, err := loadTestVectorFiles()
	if err != nil {
		t.Fatalf("Failed to load test vector files: %v", err)
	}

	testVectorKeystores, err := loadTestVectorKeystores(testVectorFiles)
	if err != nil {
		t.Fatalf("Failed to load test vector keystores: %v", err)
	}

	for i, keystore := range testVectorKeystores {
		keystoreJsonPath := filepath.Join(testVectorFolder, testVectorFiles[i])

		// Read JSON from the file
		fileData, err := ioutil.ReadFile(keystoreJsonPath)
		if err != nil {
			t.Fatalf("Failed to read file: %v", err)
		}

		var expectedJson map[string]interface{}
		err = json.Unmarshal(fileData, &expectedJson)
		if err != nil {
			t.Fatalf("Failed to unmarshal JSON from file: %v", err)
		}

		// Compare the serialized JSON
		keystoreJson, err := keystore.ToJSON()
		if err != nil {
			t.Fatalf("Failed to serialize keystore: %v", err)
		}

		var actualJson map[string]interface{}
		err = json.Unmarshal([]byte(keystoreJson), &actualJson)
		if err != nil {
			t.Fatalf("Failed to unmarshal serialized keystore JSON: %v", err)
		}

		if !jsonEqual(actualJson, expectedJson) {
			t.Fatalf("Keystore JSON mismatch for file %s", testVectorFiles[i])
		}
	}
}

func TestEncryptDecryptTestVectors(t *testing.T) {
	testVectorFiles, err := loadTestVectorFiles()
	if err != nil {
		t.Fatalf("Failed to load test vector files: %v", err)
	}

	testVectorKeystores, err := loadTestVectorKeystores(testVectorFiles)
	if err != nil {
		t.Fatalf("Failed to load test vector keystores: %v", err)
	}

	for _, keystore := range testVectorKeystores {
		aesIv, _ := hex.DecodeString(keystore.Crypto.Cipher.Params["iv"].(string))
		kdfSalt, _ := hex.DecodeString(keystore.Crypto.Kdf.Params["salt"].(string))
		path := keystore.Path

		// Determine the keystore type (PBKDF2 or Scrypt)
		var generatedKeystore *Keystore
		var baseKeystore *Keystore
		if strings.Contains(keystore.Crypto.Kdf.Function, "pbkdf") {
			baseKeystore = &NewPbkdf2Keystore().Keystore
		} else {
			baseKeystore = &NewScryptKeystore().Keystore
		}

		baseKeystore.Curve = keystore.Curve
		generatedKeystore, err = baseKeystore.Encrypt(testVectorSecret, testVectorPassword, path, kdfSalt, aesIv)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Decrypt and check if the secret matches the original
		decryptedSecret, err := generatedKeystore.Decrypt(testVectorPassword)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		assert.Equal(t, decryptedSecret, testVectorSecret)
	}
}

// TestGeneratedKeystores replicates the Python test using Go
func TestGeneratedKeystores(t *testing.T) {

	testVectorFiles, err := loadTestVectorFiles()
	if err != nil {
		t.Fatalf("Failed to load test vector files: %v", err)
	}

	testVectorKeystores, err := loadTestVectorKeystores(testVectorFiles)
	if err != nil {
		t.Fatalf("Failed to load test vector keystores: %v", err)
	}

	// Iterate over the test vector keystores and run the tests
	for _, tv := range testVectorKeystores {
		// Retrieve AES IV and KDF salt from the test vector
		aesIVHex, ok := tv.Crypto.Cipher.Params["iv"].(string)
		if !ok {
			t.Fatalf("Failed to retrieve AES IV from test vector keystore")
		}

		aesIV, err := hex.DecodeString(aesIVHex)
		if err != nil {
			t.Fatalf("Failed to decode AES IV: %v", err)
		}

		kdfSaltHex, ok := tv.Crypto.Kdf.Params["salt"].(string)
		if !ok {
			t.Fatalf("Failed to retrieve KDF salt from test vector keystore")
		}

		kdfSalt, err := hex.DecodeString(kdfSaltHex)
		if err != nil {
			t.Fatalf("Failed to decode KDF salt: %v", err)
		}

		// Create a new keystore based on the KDF function
		generatedKeystore, err := tv.Encrypt(testVectorSecret, testVectorPassword, tv.Path, kdfSalt, aesIV)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		assert.Equal(t, tv.Crypto, generatedKeystore.Crypto)
	}
}

func TestEncryptDecryptPbkdf2RandomIv(t *testing.T) {
	newKeystore := NewPbkdf2Keystore()
	newKeystore.Curve = "bls12-381"
	_, err := newKeystore.Encrypt(testVectorSecret, testVectorPassword, "random_iv", nil, nil)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decryptedMessage, err := newKeystore.Decrypt(testVectorPassword)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	assert.Equal(t, decryptedMessage, testVectorSecret)
}

func TestEncryptDecryptScryptRandomIv(t *testing.T) {
	newKeystore := NewScryptKeystore()
	newKeystore.Curve = "bls12-381"

	_, err := newKeystore.Encrypt(testVectorSecret, testVectorPassword, "random_iv", nil, nil)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decryptedMessage, err := newKeystore.Decrypt(testVectorPassword)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	assert.Equal(t, decryptedMessage, testVectorSecret)
}

func TestEncryptDecryptIncorrectPassword(t *testing.T) {
	newKeystore := NewScryptKeystore()
	newKeystore.Curve = "bls12-381"

	_, err := newKeystore.Encrypt(testVectorSecret, testVectorPassword, "random_iv", nil, nil)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	_, err = newKeystore.Decrypt(testVectorPassword + "incorrect_password")
	if err == nil {
		t.Fatalf("decryption should have failed for wrong password")
	}
}

func TestProcessPassword(t *testing.T) {
	// Define test cases in a struct similar to parametrize in pytest
	tests := []struct {
		password          string
		processedPassword []byte
	}{
		{password: "\a", processedPassword: []byte{}},
		{password: "\b", processedPassword: []byte{}},
		{password: "\t", processedPassword: []byte{}},
		{password: "a", processedPassword: []byte("a")},
		{password: "abc", processedPassword: []byte("abc")},
		{password: "a\bc", processedPassword: []byte("ac")},
	}

	// Loop over the test cases
	for _, tt := range tests {
		// Run each test case
		t.Run(tt.password, func(t *testing.T) {
			// Call the _process_password function
			var ks Keystore
			result := ks.processPassword(tt.password)

			// Check if the processed password matches the expected result
			if string(result) != string(tt.processedPassword) {
				t.Errorf("expected %s, got %s", tt.processedPassword, result)
			}
		})
	}
}

// Helper function to compare two JSON objects for equality
func jsonEqual(a, b map[string]interface{}) bool {
	aBytes, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bBytes, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(aBytes) == string(bBytes)
}
