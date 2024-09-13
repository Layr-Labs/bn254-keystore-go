package bls_keystore_bn254_go

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/text/unicode/norm"
	"io/ioutil"
	"os"
	"path/filepath"
	"unicode"
)

// Keystore struct
type Keystore struct {
	Crypto      KeystoreCrypto `json:"crypto"`
	Description string         `json:"description"`
	PubKey      string         `json:"pubkey"`
	Path        string         `json:"path"`
	UUID        string         `json:"uuid"`
	Version     int            `json:"version"`
}

// KeystoreCrypto represents cryptographic parameters within the keystore
type KeystoreCrypto struct {
	Kdf struct {
		Function string                 `json:"function"`
		Params   map[string]interface{} `json:"params"`
		Message  string                 `json:"message"`
	} `json:"kdf"`
	Checksum struct {
		Function string                 `json:"function"`
		Params   map[string]interface{} `json:"params"`
		Message  string                 `json:"message"`
	} `json:"checksum"`
	Cipher struct {
		Function string                 `json:"function"`
		Params   map[string]interface{} `json:"params"`
		Message  string                 `json:"message"`
	} `json:"cipher"`
}

// ChecksumMessage returns the decoded checksum message as a byte slice
func (kc *KeystoreCrypto) ChecksumMessage() ([]byte, error) {
	return hex.DecodeString(kc.Checksum.Message)
}

// CipherMessage returns the decoded cipher message (ciphertext) as a byte slice
func (kc *KeystoreCrypto) CipherMessage() ([]byte, error) {
	return hex.DecodeString(kc.Cipher.Message)
}

// CipherParams retrieves the cipher parameters (e.g., IV) as a map
func (kc *KeystoreCrypto) CipherParams() map[string]interface{} {
	return kc.Cipher.Params
}

// IV retrieves the initialization vector (IV) from cipher params
func (kc *KeystoreCrypto) IV() ([]byte, error) {
	ivStr, ok := kc.Cipher.Params["iv"].(string)
	if !ok {
		return nil, errors.New("invalid IV format")
	}
	return hex.DecodeString(ivStr)
}

// KdfParams retrieves the KDF parameters
func (kc *KeystoreCrypto) KdfParams() map[string]interface{} {
	return kc.Kdf.Params
}

// FromJSON initializes a Keystore from a JSON object
func (ks *Keystore) FromJSON(data map[string]interface{}) error {
	cryptoData, ok := data["crypto"].(map[string]interface{})
	if !ok {
		return errors.New("invalid crypto field")
	}

	crypto, err := KeystoreCryptoFromJSON(cryptoData)
	if err != nil {
		return err
	}

	ks.Crypto = *crypto
	ks.Path, _ = data["path"].(string)
	ks.UUID, _ = data["uuid"].(string)
	version, _ := data["version"].(float64)
	ks.Version = int(version)
	ks.Description, _ = data["description"].(string)
	ks.PubKey, _ = data["pubkey"].(string)

	return nil
}

// KeystoreCryptoFromJSON parses the KeystoreCrypto from the provided JSON data
func KeystoreCryptoFromJSON(data map[string]interface{}) (*KeystoreCrypto, error) {
	crypto := &KeystoreCrypto{}

	// Parse KDF section
	kdfData, ok := data["kdf"].(map[string]interface{})
	if !ok {
		return nil, errors.New("missing or invalid 'kdf' field in JSON")
	}
	kdfFunction, ok := kdfData["function"].(string)
	if !ok {
		return nil, errors.New("missing 'function' in 'kdf'")
	}
	kdfMessage, ok := kdfData["message"].(string)
	if !ok {
		return nil, errors.New("missing 'message' in 'kdf'")
	}
	kdfParams, ok := kdfData["params"].(map[string]interface{})
	if !ok {
		return nil, errors.New("missing 'params' in 'kdf'")
	}
	crypto.Kdf.Function = kdfFunction
	crypto.Kdf.Message = kdfMessage
	crypto.Kdf.Params = kdfParams

	// Parse Checksum section
	checksumData, ok := data["checksum"].(map[string]interface{})
	if !ok {
		return nil, errors.New("missing or invalid 'checksum' field in JSON")
	}
	checksumFunction, ok := checksumData["function"].(string)
	if !ok {
		return nil, errors.New("missing 'function' in 'checksum'")
	}
	checksumMessage, ok := checksumData["message"].(string)
	if !ok {
		return nil, errors.New("missing 'message' in 'checksum'")
	}
	checksumParams, ok := checksumData["params"].(map[string]interface{})
	if !ok {
		return nil, errors.New("missing 'params' in 'checksum'")
	}
	crypto.Checksum.Function = checksumFunction
	crypto.Checksum.Message = checksumMessage
	crypto.Checksum.Params = checksumParams

	// Parse Cipher section
	cipherData, ok := data["cipher"].(map[string]interface{})
	if !ok {
		return nil, errors.New("missing or invalid 'cipher' field in JSON")
	}
	cipherFunction, ok := cipherData["function"].(string)
	if !ok {
		return nil, errors.New("missing 'function' in 'cipher'")
	}
	cipherMessage, ok := cipherData["message"].(string)
	if !ok {
		return nil, errors.New("missing 'message' in 'cipher'")
	}
	cipherParams, ok := cipherData["params"].(map[string]interface{})
	if !ok {
		return nil, errors.New("missing 'params' in 'cipher'")
	}
	crypto.Cipher.Function = cipherFunction
	crypto.Cipher.Message = cipherMessage
	crypto.Cipher.Params = cipherParams

	return crypto, nil
}

// FromFile reads a keystore from a file
func (ks *Keystore) FromFile(path string) error {
	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	var jsonData map[string]interface{}
	err = json.Unmarshal(fileData, &jsonData)
	if err != nil {
		return err
	}

	return ks.FromJSON(jsonData)
}

func (ks *Keystore) Encrypt(secret []byte, password string, path string, kdfSalt, aesIV []byte) (*Keystore, error) {
	// Ensure secret and password are not empty
	if len(secret) == 0 || password == "" {
		return nil, errors.New("secret and password cannot be empty")
	}

	// Generate random salt and IV if not provided
	if kdfSalt == nil || len(kdfSalt) == 0 {
		kdfSalt = generateRandomBytes(32) // 256-bit salt
	}
	ks.Crypto.Kdf.Params["salt"] = hex.EncodeToString(kdfSalt)

	if aesIV == nil || len(aesIV) == 0 {
		aesIV = generateRandomBytes(16) // 128-bit IV
	}
	ks.Crypto.Cipher.Params["iv"] = hex.EncodeToString(aesIV)

	// Initialize the keystore
	ks.UUID = generateUUID()
	ks.Path = path

	var decryptionKey []byte
	var err error

	// Switch based on KDF function
	decryptionKey, err = ks.Kdf(ks._processPassword(password), kdfSalt)

	if err != nil {
		return nil, err
	}

	// Encrypt the secret using AES-128-CTR
	encryptedSecret, err := AES128CTR(decryptionKey[:16], aesIV, secret)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %v", err)
	}
	ks.Crypto.Cipher.Message = hex.EncodeToString(encryptedSecret)

	checksum := sha256Hash(append(decryptionKey[16:], encryptedSecret...))
	ks.Crypto.Checksum.Function = "sha256"
	ks.Crypto.Checksum.Message = hex.EncodeToString(checksum[:])
	ks.Path = path

	ks.PubKey, err = blsSkToPk(secret)
	if err != nil {
		return nil, err
	}

	return ks, nil
}

// _processPassword processes the password as per the NFKD UTF-8 requirement of EIP-2335
func (ks *Keystore) _processPassword(password string) []byte {
	// Normalize the password to NFKD
	normPassword := norm.NFKD.String(password)

	// Remove control characters
	filteredPassword := ""
	for _, char := range normPassword {
		if !unicode.IsControl(char) {
			filteredPassword += string(char)
		}
	}

	// Encode to UTF-8 and return as byte slice
	return []byte(filteredPassword)
}

// Kdf performs the key derivation function based on the provided crypto function
func (ks *Keystore) Kdf(password []byte, salt []byte) ([]byte, error) {

	dkLen, err := getKeyFromMap(ks.Crypto.Kdf.Params, "dklen")
	if err != nil {
		return nil, err
	}

	if ks.Crypto.Kdf.Function == "scrypt" {
		r, err := getKeyFromMap(ks.Crypto.Kdf.Params, "r")
		if err != nil {
			return nil, err
		}
		p, err := getKeyFromMap(ks.Crypto.Kdf.Params, "p")
		if err != nil {
			return nil, err
		}
		n, err := getKeyFromMap(ks.Crypto.Kdf.Params, "n")
		if err != nil {
			return nil, err
		}
		return Scrypt(password, salt, int(n.(float64)), int(r.(float64)), int(p.(float64)), int(dkLen.(float64)))

	} else if ks.Crypto.Kdf.Function == "pbkdf2" {
		c, err := getKeyFromMap(ks.Crypto.Kdf.Params, "c")
		if err != nil {
			return nil, err
		}
		prf, err := getKeyFromMap(ks.Crypto.Kdf.Params, "prf")
		if err != nil {
			return nil, err
		}

		return PBKDF2(password, salt, int(dkLen.(float64)), int(c.(float64)), prf.(string))
	}
	return nil, errors.New("unsupported KDF function")
}

// ToJSON serializes the Keystore struct into a JSON string.
func (ks *Keystore) ToJSON() (string, error) {
	// Marshal the Keystore struct to JSON
	data, err := json.Marshal(ks)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Save writes the Keystore to a file in JSON format
func (ks *Keystore) Save(fileFolder string) error {
	filePath := filepath.Join(fileFolder, ks.UUID+".json")
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(ks); err != nil {
		return err
	}

	// Set file permissions to read-only for owner and group if on Unix systems
	if os.Getenv("GOOS") == "linux" || os.Getenv("GOOS") == "darwin" {
		return os.Chmod(filePath, 0440)
	}
	return nil
}

// Decrypt retrieves the secret (BLS SK) by decrypting with the password
func (ks *Keystore) Decrypt(password string) ([]byte, error) {
	// Derive the decryption key using the KDF

	kdfSalt, err := hex.DecodeString(ks.Crypto.Kdf.Params["salt"].(string))
	if err != nil {
		return nil, err
	}

	decryptionKey, err := ks.Kdf(ks._processPassword(password), kdfSalt)
	if err != nil {
		return nil, err
	}

	// Verify the checksum
	cMessage, err := ks.Crypto.CipherMessage()
	if err != nil {
		return nil, err
	}

	checksumInput := append(decryptionKey[16:32], cMessage...) // The decryption key and cipher message
	checksum := ks.cryptoChecksum(checksumInput)
	expectedChecksum, err := ks.Crypto.ChecksumMessage()
	if err != nil {
		return nil, err
	}

	if !equal(checksum, expectedChecksum) {
		return nil, errors.New("checksum message error")
	}

	// Decrypt the cipher message
	decryptedMessage, err := ks.aes128CTRDecrypt(decryptionKey[:16], cMessage, ks.Crypto.CipherParams())
	if err != nil {
		return nil, err
	}

	return decryptedMessage, nil
}

// cryptoChecksum calculates the SHA-256 hash for checksum verification
func (ks *Keystore) cryptoChecksum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// aes128CTRDecrypt decrypts a message using AES-128-CTR
func (ks *Keystore) aes128CTRDecrypt(key, ciphertext []byte, params map[string]interface{}) ([]byte, error) {
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

// Utility function to check if two byte slices are equal
func equal(a, b []byte) bool {
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