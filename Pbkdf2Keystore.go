package bls_keystore_bn254_go

// Pbkdf2Keystore embeds the Keystore and initializes specific cryptographic parameters
type Pbkdf2Keystore struct {
	Keystore
}

// NewPbkdf2Keystore initializes a new Pbkdf2Keystore with the PBKDF2 KDF and AES-128-CTR cipher
func NewPbkdf2Keystore() *Pbkdf2Keystore {
	return &Pbkdf2Keystore{
		Keystore: Keystore{
			Crypto: KeystoreCrypto{
				Kdf: struct {
					Function string                 `json:"function"`
					Params   map[string]interface{} `json:"params"`
					Message  string                 `json:"message"`
				}{
					Function: "pbkdf2",
					Params: map[string]interface{}{
						"c":     float64(1 << 18), // 2^18 iterations
						"dklen": float64(32),
						"prf":   "hmac-sha256",
					},
					Message: "", // This will be set when used
				},
				Checksum: struct {
					Function string                 `json:"function"`
					Params   map[string]interface{} `json:"params"`
					Message  string                 `json:"message"`
				}{
					Message:  "", // This will be set when used
					Function: "sha256",
					Params:   map[string]interface{}{},
				},
				Cipher: struct {
					Function string                 `json:"function"`
					Params   map[string]interface{} `json:"params"`
					Message  string                 `json:"message"`
				}{
					Message:  "", // This will be set when encrypting/decrypting
					Params:   map[string]interface{}{},
					Function: "aes-128-ctr",
				},
			},
		},
	}
}
