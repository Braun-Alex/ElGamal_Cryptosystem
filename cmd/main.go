package main

import (
	"ElGamal_Cryptosystem/pkg/keypair"
	"ElGamal_Cryptosystem/pkg/signature"
	"fmt"
)

func main() {
	message := "Hi"
	privateKey, publicKey, p, g := keypair.GenerateKeypair()
	r, s := signature.Sign(message, privateKey, p, g)
	isValidSignature := signature.Verify(message, publicKey, r, s, p, g)
	if isValidSignature {
		fmt.Print("Signature is valid")
	} else {
		fmt.Print("Signature is not valid")
	}
}
