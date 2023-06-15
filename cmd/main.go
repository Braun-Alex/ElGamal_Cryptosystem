package main

import (
	"ElGamal_Cryptosystem/pkg/encryption"
	"ElGamal_Cryptosystem/pkg/keypair"
	"ElGamal_Cryptosystem/pkg/signature"
	"fmt"
)

func main() {
	message := "ZK-STARK has big impact on StarkNet"
	var answer string
	privateKey, publicKey := keypair.GenerateKeypair()
	r, s := signature.Sign(message, privateKey)
	isValidSignature := signature.Verify(message, publicKey, r, s)
	if isValidSignature {
		answer = "yes\n"
	} else {
		answer = "no\n"
	}
	cipherText := encryption.Encrypt(message, publicKey)
	decryptedMessage := encryption.Decrypt(cipherText, privateKey)
	// Deferred invoking has been implemented for the correct displaying all the data in the console
	defer fmt.Print("Decrypted message: ", decryptedMessage)
	defer fmt.Print("Ciphertext: ", cipherText, "\n")
	defer fmt.Print("********* ElGamal encryption and decryption *********\n")
	defer fmt.Print("Signature is valid: ", answer)
	defer fmt.Printf("Parameter S: %d\n", s)
	defer fmt.Printf("Parameter R: %d\n", r)
	defer fmt.Print("********* ElGamal signing and verification *********\n")
	defer fmt.Print("Message: \"", message, "\"\n")
	defer fmt.Printf("Public key: %d\n", publicKey)
	defer fmt.Printf("Private key: %d\n", privateKey)
	defer fmt.Print("*********** ElGamal cryptosystem ***********\n")
}
