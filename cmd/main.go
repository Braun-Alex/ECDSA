package main

import (
	"fmt"
	"github.com/Braun-Alex/ECDSA/pkg/ecdsa"
	"github.com/Braun-Alex/ECDSA/pkg/keypair"
	"github.com/Braun-Alex/ECDSA/pkg/utils"
)

func main() {
	message := "ZK-STARK has big impact on StarkNet"
	var answer string
	privateKey, publicKey := keypair.GenerateKeypair()
	r, s := ecdsa.Sign(message, privateKey)
	isValidSignature := ecdsa.Verify(message, publicKey, r, s)
	if isValidSignature {
		answer = "yes"
	} else {
		answer = "no"
	}
	fmt.Print("*********** Keypair and message ***********\n")
	fmt.Printf("Private key: %s\n", utils.SerializePrivateKey(privateKey))
	fmt.Printf("Public key: %s\n", utils.SerializePublicKey(publicKey))
	fmt.Print("Message: \"", message, "\"\n")
	fmt.Print("********* ECDSA *********\n")
	sigR, sigS := utils.SerializeSignature(r, s)
	fmt.Printf("Parameter R: %s\n", sigR)
	fmt.Printf("Parameter S: %s\n", sigS)
	fmt.Print("Signature is valid: ", answer)
}
