package ecdsa

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/Braun-Alex/elliptic-wrapper/pkg/ec"
	"golang.org/x/crypto/sha3"
	"math/big"
)

func Sign(message string, privateKey *big.Int) (r, s *big.Int) {
	// Generating session key from [0; n-1]
	basePointOrder := elliptic.P521().Params().N
	k, err := rand.Int(rand.Reader, basePointOrder)
	// Checking for error and that session key must be not equal 0
	if err != nil || k.Cmp(big.NewInt(0)) == 0 {
		panic("Session key could not be generated")
	}
	// Computing kG
	kPoint := ec.ScalarMult(*k, ec.BasePointGGet())
	// Computing r = kG.x (mod n)
	r.Mod(kPoint.X, basePointOrder)
	// If r == 0 then repeat generating of session key
	if r.Cmp(big.NewInt(0)) == 0 {
		r, s = Sign(message, privateKey)
		return
	}
	// Converting hash of the message to decimal big number
	buffer := new(big.Int)
	messageHash := sha3.Sum512([]byte(message))
	hashDecimal := new(big.Int).SetBytes(messageHash[:])
	// Generating of component s = (hashM + privateKey * r) * k^(-1) (mod n)
	buffer.Mul(privateKey, r)
	buffer.Add(hashDecimal, buffer)
	k.ModInverse(k, basePointOrder)
	s.Mul(buffer, k)
	s.Mod(s, basePointOrder)
	// If s == 0 then repeat signing
	if s.Cmp(big.NewInt(0)) == 0 {
		r, s = Sign(message, privateKey)
		return
	}
	return
}
