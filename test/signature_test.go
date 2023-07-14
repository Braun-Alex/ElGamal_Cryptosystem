package test

import (
	"ElGamal_Cryptosystem/pkg/keypair"
	"ElGamal_Cryptosystem/pkg/signature"
	"math/big"
	"testing"
)

func TestCorrectSignature(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, publicKey := keypair.GenerateKeypair()
	r, s := signature.Sign(message, privateKey)
	isValidSignature := signature.Verify(message, publicKey, r, s)
	if !isValidSignature {
		test.Error("One does not accept correct ElGamal signature")
	}
}

func TestIncorrectSignatureOnDifferentData(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	anotherMessage := "LayerZero is cross-chain protocol"
	privateKey, publicKey := keypair.GenerateKeypair()
	r, s := signature.Sign(message, privateKey)
	isValidSignature := signature.Verify(anotherMessage, publicKey, r, s)
	if isValidSignature {
		test.Error("One accepts incorrect ElGamal signature on different data")
	}
}

func TestIncorrectSignatureOnDifferentKeys(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, _ := keypair.GenerateKeypair()
	_, anotherPublicKey := keypair.GenerateKeypair()
	r, s := signature.Sign(message, privateKey)
	isValidSignature := signature.Verify(message, anotherPublicKey, r, s)
	if isValidSignature {
		test.Error("One accepts incorrect ElGamal signature on another public key")
	}
}

func TestIncorrectSignatureOnIncorrectParameterR(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, _ := keypair.GenerateKeypair()
	_, anotherPublicKey := keypair.GenerateKeypair()
	r, s := signature.Sign(message, privateKey)
	r.Add(r, big.NewInt(3))
	isValidSignature := signature.Verify(message, anotherPublicKey, r, s)
	if isValidSignature {
		test.Error("One accepts incorrect ElGamal signature on changed parameter r")
	}
}

func TestIncorrectSignatureOnIncorrectParameterS(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, _ := keypair.GenerateKeypair()
	_, anotherPublicKey := keypair.GenerateKeypair()
	r, s := signature.Sign(message, privateKey)
	s.Add(s, big.NewInt(3))
	isValidSignature := signature.Verify(message, anotherPublicKey, r, s)
	if isValidSignature {
		test.Error("One accepts incorrect ElGamal signature on changed parameter s")
	}
}
