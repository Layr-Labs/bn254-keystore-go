package bls_keystore_bn254_go

import (
	"encoding/hex"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"math/big"
)

func blsSkToPk(secret []byte) (string, error) {
	// Initialize the Fr element from the secret
	var frElement fr.Element
	frElement.SetBytes(secret)

	// Get the G1 generator
	_, _, _, g2Gen := bls12381.Generators()

	// Compute the public key on G1 as pubKey = G1Gen * frElement
	var pubKey bls12381.G2Affine
	var frBigInt big.Int
	frElement.BigInt(&frBigInt)
	pubKey.ScalarMultiplication(&g2Gen, &frBigInt)

	// Get the byte representation of the public key
	publicKeyBytes := pubKey.Bytes()

	// Return the public key as a hex-encoded string
	return hex.EncodeToString(publicKeyBytes[:]), nil
}
