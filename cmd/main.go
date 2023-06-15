package main

import (
	"ElGamal_Cryptosystem/pkg/keypair"
	"ElGamal_Cryptosystem/pkg/signature"
	"fmt"
)

func main() {
	message := "Hi"
	privateKey, publicKey := keypair.GenerateKeypair()
	r, s := signature.Sign(message, privateKey)
	isValidSignature := signature.Verify(message, publicKey, r, s)
	if isValidSignature {
		fmt.Print("Signature is valid")
	} else {
		fmt.Print("Signature is not valid")
	}
}
