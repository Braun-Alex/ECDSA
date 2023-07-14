package ecdsa

import (
	"crypto/rand"
	"github.com/Braun-Alex/elliptic-wrapper/pkg/ec"
	"golang.org/x/crypto/sha3"
	"math/big"
)

func Sign(message string, privateKey *big.Int) (r, s *big.Int) {
	basePointOrder := ec.BasePointGOrderGet()
	// Generating session key from [0; n-1]
	k, err := rand.Int(rand.Reader, basePointOrder)
	// Checking for error and that session key must be not equal 0
	if err != nil || k.Cmp(big.NewInt(0)) == 0 {
		panic("Session key could not be generated")
	}
	// Computing kG
	kPoint := ec.ScalarMult(*k, ec.BasePointGGet())
	// Computing r = kG.x (mod n)
	r = new(big.Int).Mod(kPoint.X, basePointOrder)
	// If r == 0, then repeat generating of session key
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
	s = new(big.Int).Mul(buffer, k)
	s.Mod(s, basePointOrder)
	// If s == 0, then repeat signing
	if s.Cmp(big.NewInt(0)) == 0 {
		r, s = Sign(message, privateKey)
		return
	}
	return
}

func Verify(message string, publicKey ec.ElCPoint, r, s *big.Int) bool {
	basePointOrder := ec.BasePointGOrderGet()
	// Checking 1 <= r <= n-1
	if r.Cmp(big.NewInt(0)) != 1 || r.Cmp(basePointOrder) != -1 {
		return false
	}
	// Checking 1 <= s <= n-1
	if s.Cmp(big.NewInt(0)) != 1 || s.Cmp(basePointOrder) != -1 {
		return false
	}
	// Converting hash of the message to decimal big number
	messageHash := sha3.Sum512([]byte(message))
	hashDecimal := new(big.Int).SetBytes(messageHash[:])
	// Computing w = s^(-1) (mod n)
	w := new(big.Int).ModInverse(s, basePointOrder)
	// Computing u1 = hashDecimal*w (mod n)
	buffer := new(big.Int).Mul(hashDecimal, w)
	u1 := new(big.Int).Mod(buffer, basePointOrder)
	// Computing u2 = r*w (mod n)
	buffer.Mul(r, w)
	u2 := new(big.Int).Mod(buffer, basePointOrder)
	// Computing u1*G
	gPoint := ec.ScalarMult(*u1, ec.BasePointGGet())
	// Computing u2*publicKey
	qPoint := ec.ScalarMult(*u2, publicKey)
	// Computing u1*G + u2*publicKey
	xPoint := ec.AddElCPoints(gPoint, qPoint)
	// If X is infinite point, then reject signature
	if xPoint.X == nil {
		return false
	}
	// Computing v = X.x (mod n)
	v := new(big.Int).Mod(xPoint.X, basePointOrder)
	// Accept signature only and only if v == r
	return v.Cmp(r) == 0
}
