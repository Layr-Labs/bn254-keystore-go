package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unicode"

	"github.com/Layr-Labs/bn254-keystore-go/curve"
	"github.com/Layr-Labs/bn254-keystore-go/mnemonic"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"golang.org/x/text/unicode/norm"
)

type KDFFunction string

const (
	KDFScrypt KDFFunction = "scrypt"
	KDFPBKDF2 KDFFunction = "pbkdf2"

	DefaultWordListPath = "../word_lists"

	DerivationPathBN254 = "m/254/60/0/0"
)

// Keystore struct
type Keystore struct {
	Crypto      Crypto `json:"crypto"`
	Description string `json:"description"`
	PubKey      string `json:"pubkey"`
	Path        string `json:"path"`
	UUID        string `json:"uuid"`
	Version     int    `json:"version"`
	Curve       string `json:"curve"`
}

// Crypto represents cryptographic parameters within the keystore
type Crypto struct {
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
func (kc *Crypto) ChecksumMessage() ([]byte, error) {
	return hex.DecodeString(kc.Checksum.Message)
}

// CipherMessage returns the decoded cipher message (ciphertext) as a byte slice
func (kc *Crypto) CipherMessage() ([]byte, error) {
	return hex.DecodeString(kc.Cipher.Message)
}

// CipherParams retrieves the cipher parameters (e.g., IV) as a map
func (kc *Crypto) CipherParams() map[string]interface{} {
	return kc.Cipher.Params
}

// IV retrieves the initialization vector (IV) from cipher params
func (kc *Crypto) IV() ([]byte, error) {
	ivStr, ok := kc.Cipher.Params["iv"].(string)
	if !ok {
		return nil, errors.New("invalid IV format")
	}
	return hex.DecodeString(ivStr)
}

// KdfParams retrieves the KDF parameters
func (kc *Crypto) KdfParams() map[string]interface{} {
	return kc.Kdf.Params
}

// FromJSON initializes a Keystore from a JSON object
func (ks *Keystore) FromJSON(data map[string]interface{}) error {
	cryptoData, ok := data["crypto"].(map[string]interface{})
	if !ok {
		return errors.New("invalid crypto field")
	}

	crypto, err := CryptoFromJSON(cryptoData)
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
	ks.Curve, _ = data["curve"].(string)

	return nil
}

// CryptoFromJSON parses the Crypto from the provided JSON data
func CryptoFromJSON(data map[string]interface{}) (*Crypto, error) {
	crypto := &Crypto{}

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
	cleanedPath := filepath.Clean(path)
	fileData, err := os.ReadFile(cleanedPath)
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

// Encrypt encrypts the provided secret using the specified password and stores it in the Keystore.
// It utilizes AES-128-CTR encryption and a key derivation function (KDF) to securely encrypt the secret.
//
// Parameters:
//
//   - secret ([]byte): The secret data to be encrypted (e.g., a private key). Must not be empty.
//
//   - password (string): The password used to derive the encryption key via the KDF. Must not be empty.
//
//   - path (string): The derivation path of the key.
//
//   - kdfSalt ([]byte): Optional. The salt used in the key derivation function. If nil or empty, a random 256-bit salt is
//     generated.
//
//   - aesIV ([]byte): Optional. The initialization vector (IV) for AES encryption. If nil or empty, a random
//     128-bit IV is generated.
//
// Returns:
//   - *Keystore: A pointer to the Keystore instance containing the encrypted secret and associated metadata.
//   - error: An error object if any issues occur during encryption or parameter validation.
func (ks *Keystore) Encrypt(
	secret []byte,
	password string,
	path string,
	kdfSalt,
	aesIV []byte,
) (*Keystore, error) {

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
	decryptionKey, err = ks.Kdf(ks.processPassword(password), kdfSalt)

	if err != nil {
		return nil, err
	}

	// Encrypt the secret using AES-128-CTR
	encryptedSecret, err := Aes128CTREncrypt(decryptionKey[:16], aesIV, secret)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %v", err)
	}
	ks.Crypto.Cipher.Message = hex.EncodeToString(encryptedSecret)

	checksum := Sha256Hash(append(decryptionKey[16:], encryptedSecret...))
	ks.Crypto.Checksum.Function = "sha256"
	ks.Crypto.Checksum.Message = hex.EncodeToString(checksum[:])
	ks.Path = path

	ks.PubKey, err = BlsSkToPk(secret, ks.Curve)
	if err != nil {
		return nil, err
	}

	return ks, nil
}

// processPassword processes the password as per the NFKD UTF-8 requirement of EIP-2335
func (ks *Keystore) processPassword(password string) []byte {
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

// Kdf derives a cryptographic key from the provided password and salt using the key derivation function (KDF)
// specified in the Keystore's crypto parameters. It supports both "scrypt" and "pbkdf2" algorithms.
//
// Parameters:
//   - password ([]byte): The password from which the key will be derived.
//   - salt ([]byte): The cryptographic salt used in the key derivation process.
//
// Returns:
//   - []byte: The derived key as a byte slice.
//   - error: An error object if key derivation fails or if the KDF function is unsupported.
func (ks *Keystore) Kdf(password []byte, salt []byte) ([]byte, error) {

	dkLen, err := GetKeyFromMap(ks.Crypto.Kdf.Params, "dklen")
	if err != nil {
		return nil, err
	}

	if ks.Crypto.Kdf.Function == "scrypt" {
		r, err := GetKeyFromMap(ks.Crypto.Kdf.Params, "r")
		if err != nil {
			return nil, err
		}
		p, err := GetKeyFromMap(ks.Crypto.Kdf.Params, "p")
		if err != nil {
			return nil, err
		}
		n, err := GetKeyFromMap(ks.Crypto.Kdf.Params, "n")
		if err != nil {
			return nil, err
		}
		return Scrypt(password, salt, int(n.(float64)), int(r.(float64)), int(p.(float64)), int(dkLen.(float64)))

	} else if ks.Crypto.Kdf.Function == "pbkdf2" {
		c, err := GetKeyFromMap(ks.Crypto.Kdf.Params, "c")
		if err != nil {
			return nil, err
		}
		prf, err := GetKeyFromMap(ks.Crypto.Kdf.Params, "prf")
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

// SaveWithUUID writes the Keystore to a file in JSON format filename as uuid.json
func (ks *Keystore) SaveWithUUID(fileFolder string) error {
	cleanedFileFolder := filepath.Clean(fileFolder)
	filePath := filepath.Join(cleanedFileFolder, ks.UUID+".json")

	return saveFile(ks, filePath)
}

// SaveWithPubKeyHex writes the Keystore to a file in JSON format and filename as pub_key_hex.json
func (ks *Keystore) SaveWithPubKeyHex(fileFolder string) error {
	cleanedFileFolder := filepath.Clean(fileFolder)
	filePath := filepath.Join(cleanedFileFolder, ks.PubKey+".json")

	return saveFile(ks, filePath)
}

func saveFile(ks *Keystore, path string) error {
	cleanedFilePath := filepath.Clean(path)
	file, err := os.Create(cleanedFilePath)
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
		return os.Chmod(cleanedFilePath, 0440)
	}
	return nil
}

// Decrypt decrypts the encrypted secret stored in the Keystore using the provided password.
// It utilizes the key derivation function (KDF) and AES-128-CTR decryption to recover the original secret.
//
// Parameters:
// - password (string): The password used to derive the decryption key. Must match the password used during encryption.
//
// Returns:
//   - []byte: The decrypted secret (e.g., a private key).
//   - error: An error object if decryption fails due to incorrect password, checksum mismatch, or other issues.
func (ks *Keystore) Decrypt(password string) ([]byte, error) {
	// Derive the decryption key using the KDF

	kdfSalt, err := hex.DecodeString(ks.Crypto.Kdf.Params["salt"].(string))
	if err != nil {
		return nil, err
	}

	decryptionKey, err := ks.Kdf(ks.processPassword(password), kdfSalt)
	if err != nil {
		return nil, err
	}

	// Verify the checksum
	cMessage, err := ks.Crypto.CipherMessage()
	if err != nil {
		return nil, err
	}

	checksumInput := append(decryptionKey[16:32], cMessage...) // The decryption key and cipher message
	checksum := Sha256Hash(checksumInput)
	expectedChecksum, err := ks.Crypto.ChecksumMessage()
	if err != nil {
		return nil, err
	}

	if !Equal(checksum, expectedChecksum) {
		return nil, errors.New("checksum message error")
	}

	// Decrypt the cipher message
	decryptedMessage, err := ks.Aes128CTRDecrypt(decryptionKey[:16], cMessage)
	if err != nil {
		return nil, err
	}

	return decryptedMessage, nil
}

// Aes128CTRDecrypt decrypts a ciphertext using AES-128 in CTR (Counter) mode.
//
// It uses the provided key and initialization vector (IV) to decrypt the ciphertext and return the plaintext.
// The IV is obtained by calling `ks.Crypto.IV()`. Note that the `params` parameter is currently not used in this
// function.
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

type KeyPair struct {
	PrivateKey []byte
	Mnemonic   string
	Password   string
}

// NewKeyPair generates a new key pair using the provided password and mnemonic language.
func NewKeyPair(
	password string,
	language mnemonic.Language,
) (*KeyPair, error) {
	// Get the mnemonic
	pkMnemonic, err := mnemonic.GetMnemonic(language, DefaultWordListPath, nil)
	if err != nil {
		return nil, err
	}

	// Derive KeyPair
	key, err := mnemonic.MnemonicAndPathToKey(pkMnemonic, password, DerivationPathBN254)
	if err != nil {
		return nil, err
	}

	// Parse to bn254 curve
	// TODO: Take curve as param to generalize
	fpKey := new(fr.Element).SetBigInt(key)
	fpKeyBytes := fpKey.Bytes()

	// Return key pair
	return &KeyPair{
		PrivateKey: fpKeyBytes[:],
		Mnemonic:   pkMnemonic,
		Password:   password,
	}, nil
}

func NewKeyPairFromMnemonic(
	pkMnemonic string,
	password string,
) (*KeyPair, error) {
	// Derive KeyPair
	key, err := mnemonic.MnemonicAndPathToKey(pkMnemonic, password, DerivationPathBN254)
	if err != nil {
		return nil, err
	}

	// Parse to bn254 curve
	// TODO: Take curve as param to generalize
	fpKey := new(fr.Element).SetBigInt(key)
	fpKeyBytes := fpKey.Bytes()

	// Return key pair
	return &KeyPair{
		PrivateKey: fpKeyBytes[:],
		Mnemonic:   pkMnemonic,
		Password:   password,
	}, nil
}

func (k *KeyPair) Encrypt(kdfFunction KDFFunction, curve curve.Curve) (*Keystore, error) {
	var ks *Keystore
	var err error
	if kdfFunction == KDFPBKDF2 {
		pbkdfKeyStore := NewPbkdf2Keystore(curve)
		ks, err = pbkdfKeyStore.Encrypt(k.PrivateKey, k.Password, DerivationPathBN254, nil, nil)
		if err != nil {
			return nil, err
		}
	} else {
		scryptKeyStore := NewScryptKeystore(curve)
		ks, err = scryptKeyStore.Encrypt(k.PrivateKey, k.Password, DerivationPathBN254, nil, nil)
		if err != nil {
			return nil, err
		}
	}

	return ks, nil
}
