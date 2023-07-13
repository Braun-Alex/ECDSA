package keypair

import (
	"crypto/rand"
	"github.com/Braun-Alex/elliptic-wrapper/pkg/ec"
	"math/big"
)

func GenerateKeypair() (privateKey *big.Int, publicKey ec.ElCPoint) {
	privateKey, err := rand.Int(rand.Reader, ec.BasePointGOrderGet())
	if err != nil {
		panic(err)
	}
	if privateKey.Cmp(big.NewInt(0)) == 0 {
		panic("Private key could not be generated")
	}
	publicKey = ec.ScalarMult(*privateKey, ec.BasePointGGet())
	return
}
