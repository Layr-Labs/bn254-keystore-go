package keystore

// ScryptKeystore embeds the Keystore and initializes specific cryptographic parameters
type ScryptKeystore struct {
	Keystore
}

// NewScryptKeystore initializes a new ScryptKeystore with the Scrypt KDF and AES-128-CTR cipher
func NewScryptKeystore() *ScryptKeystore {
	return &ScryptKeystore{
		Keystore: Keystore{
			Crypto: Crypto{
				Kdf: struct {
					Function string                 `json:"function"`
					Params   map[string]interface{} `json:"params"`
					Message  string                 `json:"message"`
				}{
					Function: "scrypt",
					Params: map[string]interface{}{
						"dklen": float64(32),
						"n":     float64(1 << 18), // 2^18 iterations
						"r":     float64(8),
						"p":     float64(1),
					},
					Message: "",
				},
				Checksum: struct {
					Function string                 `json:"function"`
					Params   map[string]interface{} `json:"params"`
					Message  string                 `json:"message"`
				}{
					Function: "sha256",
					Params:   map[string]interface{}{},
					Message:  "",
				},
				Cipher: struct {
					Function string                 `json:"function"`
					Params   map[string]interface{} `json:"params"`
					Message  string                 `json:"message"`
				}{
					Function: "aes-128-ctr",
					Params:   map[string]interface{}{},
					Message:  "",
				},
			},
		},
	}
}
