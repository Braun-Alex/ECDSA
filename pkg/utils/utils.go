package utils

import (
	"github.com/Braun-Alex/elliptic-wrapper/pkg/ec"
	"math/big"
)

func SerializePrivateKey(privateKey *big.Int) string {
	return privateKey.Text(ec.HexEncoding)
}

func DeserializePrivateKey(privateKey string) *big.Int {
	deserializedPrivateKey, isValid := new(big.Int).SetString(privateKey, ec.HexEncoding)
	if !isValid {
		panic("Could not be deserialized private key")
	}
	return deserializedPrivateKey
}

func SerializePublicKey(publicKey ec.ElCPoint) string {
	return ec.ElCPointToString(publicKey)
}

func DeserializePublicKey(publicKey string) ec.ElCPoint {
	return ec.StringToElCPoint(publicKey)
}

func SerializeSignature(r, s *big.Int) (sigR, sigS string) {
	return r.Text(ec.HexEncoding), s.Text(ec.HexEncoding)
}

func DeserializeSignature(sigR, sigS string) (r, s *big.Int) {
	r, isValid := new(big.Int).SetString(sigR, ec.HexEncoding)
	if !isValid {
		panic("Could not be deserialized parameter R of signature")
	}
	s, isValid = new(big.Int).SetString(sigS, ec.HexEncoding)
	if !isValid {
		panic("Could not be deserialized parameter S of signature")
	}
	return r, s
}
