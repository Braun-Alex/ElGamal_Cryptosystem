package main

import (
	"ElGamal_Cryptosystem/pkg/keypair"
	"ElGamal_Cryptosystem/pkg/signature"
	"fmt"
)

func main() {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, publicKey := keypair.GenerateKeypair()
	fmt.Print("*********** ElGamal cryptosystem ***********\n")
	defer fmt.Printf("Private key: %d\n", privateKey)
	defer fmt.Printf("Public key: %d\n", publicKey)
	fmt.Print("Message: \"", message, "\"\n")
	r, s := signature.Sign(message, privateKey)
	isValidSignature := signature.Verify(message, publicKey, r, s)
	fmt.Print("********* ElGamal signing *********\n")
	defer fmt.Printf("Parameter R: %d\n", r)
	defer fmt.Printf("Parameter S: %s\n", s)
	fmt.Print("Signature is valid: ")
	if isValidSignature {
		fmt.Print("yes\n")
	} else {
		fmt.Print("no\n")
	}
}
