package main

import (
	"fmt"
	"github.com/Braun-Alex/ECDSA/pkg/ecdsa"
	"github.com/Braun-Alex/ECDSA/pkg/keypair"
	"github.com/Braun-Alex/elliptic-wrapper/pkg/ec"
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
	fmt.Printf("Private key: %s\n", privateKey.Text(ec.HexEncoding))
	fmt.Printf("Public key: %s\n", ec.ElCPointToString(publicKey))
	fmt.Print("Message: \"", message, "\"\n")
	fmt.Print("********* ECDSA *********\n")
	fmt.Printf("Parameter R: %s\n", r.Text(ec.HexEncoding))
	fmt.Printf("Parameter S: %s\n", r.Text(ec.HexEncoding))
	fmt.Print("Signature is valid: ", answer)
}
