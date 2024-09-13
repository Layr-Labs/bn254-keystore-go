package bls_keystore_bn254_go

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// pathToNodes maps from a path string to a slice of indices, where each index represents the corresponding level in the path.
func pathToNodes(path string) ([]int, error) {
	// Remove any spaces from the path
	path = strings.ReplaceAll(path, " ", "")

	// Ensure the path is valid
	validChars := "m1234567890/"
	for _, char := range path {
		if !strings.ContainsRune(validChars, char) {
			return nil, fmt.Errorf("invalid path: %s", path)
		}
	}

	// Split the path by `/`
	indices := strings.Split(path, "/")

	// Check if the first character is `m`
	if indices[0] != "m" {
		return nil, fmt.Errorf("the first character of path should be `m`. Got %s", indices[0])
	}

	// Remove the `m` from the path
	indices = indices[1:]

	// Convert the remaining strings to integers
	var result []int
	for _, index := range indices {
		intVal, err := strconv.Atoi(index)
		if err != nil {
			return nil, fmt.Errorf("invalid index in path: %s", index)
		}
		result = append(result, intVal)
	}

	return result, nil
}

// mnemonicAndPathToKey derives the secret key (SK) at position `path`, derived from `mnemonic`.
// The password is used to be compliant with BIP39 mnemonics that use passwords.
func mnemonicAndPathToKey(mnemonic, password, path string) (*big.Int, error) {
	// Get the seed from the mnemonic and password (assuming getSeed is implemented)
	seed, err := GetSeed(mnemonic, password)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %v", err)
	}

	// Derive the master secret key (assuming deriveMasterSK is implemented)
	sk, err := deriveMasterSK(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive master SK: %v", err)
	}

	// Convert the path to nodes (indices)
	nodes, err := pathToNodes(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse path: %v", err)
	}

	// Derive the child SK at each node (assuming deriveChildSK is implemented)
	for _, node := range nodes {
		sk, err = deriveChildSK(sk, uint32(node))
		if err != nil {
			return nil, fmt.Errorf("failed to derive child SK at node %d: %v", node, err)
		}
	}

	return sk, nil
}
