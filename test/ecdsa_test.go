package test

import (
	"github.com/Braun-Alex/ECDSA/pkg/ecdsa"
	"github.com/Braun-Alex/ECDSA/pkg/keypair"
	"math/big"
	"testing"
)

func TestCorrectSignature(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, publicKey := keypair.GenerateKeypair()
	r, s := ecdsa.Sign(message, privateKey)
	isValidSignature := ecdsa.Verify(message, publicKey, r, s)
	if !isValidSignature {
		test.Errorf("One does not accept correct ECDSA signature")
	}
}

func TestIncorrectSignatureOnDifferentData(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	anotherMessage := "LayerZero is cross-chain protocol"
	privateKey, publicKey := keypair.GenerateKeypair()
	r, s := ecdsa.Sign(message, privateKey)
	isValidSignature := ecdsa.Verify(anotherMessage, publicKey, r, s)
	if isValidSignature {
		test.Errorf("One accepts incorrect ECDSA signature on different data")
	}
}

func TestIncorrectSignatureOnDifferentKeys(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, _ := keypair.GenerateKeypair()
	_, anotherPublicKey := keypair.GenerateKeypair()
	r, s := ecdsa.Sign(message, privateKey)
	isValidSignature := ecdsa.Verify(message, anotherPublicKey, r, s)
	if isValidSignature {
		test.Errorf("One accepts incorrect ECDSA signature on another public key")
	}
}

func TestIncorrectSignatureOnIncorrectParameterR(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, _ := keypair.GenerateKeypair()
	_, anotherPublicKey := keypair.GenerateKeypair()
	r, s := ecdsa.Sign(message, privateKey)
	r.Add(r, big.NewInt(3))
	isValidSignature := ecdsa.Verify(message, anotherPublicKey, r, s)
	if isValidSignature {
		test.Errorf("One accepts incorrect ECDSA signature on changed parameter r")
	}
}

func TestIncorrectSignatureOnIncorrectParameterS(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, _ := keypair.GenerateKeypair()
	_, anotherPublicKey := keypair.GenerateKeypair()
	r, s := ecdsa.Sign(message, privateKey)
	s.Add(s, big.NewInt(3))
	isValidSignature := ecdsa.Verify(message, anotherPublicKey, r, s)
	if isValidSignature {
		test.Errorf("One accepts incorrect ECDSA signature on changed parameter s")
	}
}
