package test

import (
	"github.com/Braun-Alex/ECDSA/pkg/ecdsa"
	"github.com/Braun-Alex/ECDSA/pkg/keypair"
	"github.com/Braun-Alex/ECDSA/pkg/utils"
	"github.com/Braun-Alex/elliptic-wrapper/pkg/ec"
	"math/big"
	"testing"
)

func TestCorrectSignature(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, publicKey := keypair.GenerateKeypair()
	r, s := ecdsa.Sign(message, privateKey)
	isValidSignature := ecdsa.Verify(message, publicKey, r, s)
	if !isValidSignature {
		test.Error("One does not accept correct ECDSA signature")
	}
}

func TestIncorrectSignatureOnDifferentData(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	anotherMessage := "LayerZero is cross-chain protocol"
	privateKey, publicKey := keypair.GenerateKeypair()
	r, s := ecdsa.Sign(message, privateKey)
	isValidSignature := ecdsa.Verify(anotherMessage, publicKey, r, s)
	if isValidSignature {
		test.Error("One accepts incorrect ECDSA signature on different data")
	}
}

func TestIncorrectSignatureOnDifferentKeys(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, _ := keypair.GenerateKeypair()
	_, anotherPublicKey := keypair.GenerateKeypair()
	r, s := ecdsa.Sign(message, privateKey)
	isValidSignature := ecdsa.Verify(message, anotherPublicKey, r, s)
	if isValidSignature {
		test.Error("One accepts incorrect ECDSA signature on another public key")
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
		test.Error("One accepts incorrect ECDSA signature on changed parameter r")
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
		test.Error("One accepts incorrect ECDSA signature on changed parameter s")
	}
}

func TestCorrectPrivateKeySerializationAndDeserialization(test *testing.T) {
	privateKey, _ := keypair.GenerateKeypair()
	serializedPrivateKey := utils.SerializePrivateKey(privateKey)
	deserializedPrivateKey := utils.DeserializePrivateKey(serializedPrivateKey)
	if deserializedPrivateKey.Cmp(privateKey) != 0 {
		test.Error("Deserialization and serialization of private key have not been properly " +
			"implemented")
	}
}

func TestCorrectPublicKeySerializationAndDeserialization(test *testing.T) {
	_, publicKey := keypair.GenerateKeypair()
	serializedPublicKey := utils.SerializePublicKey(publicKey)
	deserializedPublicKey := utils.DeserializePublicKey(serializedPublicKey)
	if !ec.Eq(deserializedPublicKey, publicKey) {
		test.Error("Deserialization and serialization of public key have not been properly " +
			"implemented")
	}
}

func TestCorrectSignatureSerializationAndDeserialization(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, _ := keypair.GenerateKeypair()
	r, s := ecdsa.Sign(message, privateKey)
	serializedR, serializedS := utils.SerializeSignature(r, s)
	deserializedR, deserializedS := utils.DeserializeSignature(serializedR, serializedS)
	if deserializedR.Cmp(r) != 0 || deserializedS.Cmp(s) != 0 {
		test.Error("Deserialization and serialization of signature have not been properly " +
			"implemented")
	}
}
