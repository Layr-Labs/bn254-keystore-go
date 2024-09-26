package curve

import (
	"encoding/hex"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381Fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254Fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type Curve string

const (
	BLS12381 Curve = "bls12-381"
	BN254    Curve = "bn254"
)

type Ops struct {
	GenerateG2PubKey func(secret []byte) string
	GenerateG1PubKey func(secret []byte) string
}

var OpsMap = map[Curve]Ops{
	BLS12381: {
		GenerateG2PubKey: func(secret []byte) string {
			_, _, _, g2Gen := bls12381.Generators()
			var frBigInt big.Int
			var frElement bls12381Fr.Element
			frElement.SetBytes(secret)
			frElement.BigInt(&frBigInt)

			var pubKey bls12381.G2Affine
			publicKeyBytes := pubKey.ScalarMultiplication(&g2Gen, &frBigInt).Bytes()
			return hex.EncodeToString(publicKeyBytes[:])
		},
		GenerateG1PubKey: func(secret []byte) string {
			_, _, g1Gen, _ := bls12381.Generators()
			var frBigInt big.Int
			var frElement bls12381Fr.Element
			frElement.SetBytes(secret)
			frElement.BigInt(&frBigInt)

			var pubKey bls12381.G1Affine
			publicKeyBytes := pubKey.ScalarMultiplication(&g1Gen, &frBigInt).Bytes()
			return hex.EncodeToString(publicKeyBytes[:])
		},
	},
	BN254: {
		GenerateG2PubKey: func(secret []byte) string {
			_, _, _, g2Gen := bn254.Generators()
			var frBigInt big.Int
			var frElement bn254Fr.Element
			frElement.SetBytes(secret)
			frElement.BigInt(&frBigInt)

			var pubKey bn254.G2Affine
			publicKeyBytes := pubKey.ScalarMultiplication(&g2Gen, &frBigInt).Bytes()
			return hex.EncodeToString(publicKeyBytes[:])
		},
		GenerateG1PubKey: func(secret []byte) string {
			_, _, g1Gen, _ := bn254.Generators()
			var frBigInt big.Int
			var frElement bn254Fr.Element
			frElement.SetBytes(secret)
			frElement.BigInt(&frBigInt)

			var pubKey bn254.G1Affine
			publicKeyBytes := pubKey.ScalarMultiplication(&g1Gen, &frBigInt).Bytes()
			return hex.EncodeToString(publicKeyBytes[:])
		},
	},
}
