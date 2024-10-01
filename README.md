# EIP 2335 Compatible Keystore using BN254

### Description
This is a mechanism for storing private keys. It is a JSON file that encrypts a private key and is the standard for interchanging keys between devices as until a user provides their password, their key is safe.
Refer EIP-2335 for more details.

### Warning & Disclaimer
This code is unaudited and under construction. This is experimental software and is provided on an "as is" and "as available" basis and may not work at all. It should not be used in production.

### Usage
#### Installation
```bash
go get github.com/Layr-Labs/bn254-keystore-go
```

#### Example

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/Layr-Labs/bn254-keystore-go/keystore"
)

func main() {
	// Create a new bn254 key
	ks, err := keystore.NewKeyPair("p@$$w0rd", "english")

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Mnemonic: ", ks.Mnemonic)
	fmt.Println("Private Key Hex: ", hex.EncodeToString(ks.PrivateKey))
}
```