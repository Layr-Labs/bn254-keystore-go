package curve

import (
	"encoding/hex"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381Fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254Fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type Ops struct {
	GenerateG2PubKey func(secret []byte) string
}

var OpsMap = map[string]Ops{
	"bls12-381": {
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
	},
	"bn254": {
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
	},
}
