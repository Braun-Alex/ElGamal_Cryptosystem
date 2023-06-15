package test

import (
	"ElGamal_Cryptosystem/pkg/encryption"
	"ElGamal_Cryptosystem/pkg/keypair"
	"math/big"
	"testing"
)

func TestIncorrectDecryptionOnDifferentCiphertexts(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, publicKey := keypair.GenerateKeypair()
	cipherText := encryption.Encrypt(message, publicKey)
	cipherText[0].Add(cipherText[0], big.NewInt(3))
	decryptedMessage := encryption.Decrypt(cipherText, privateKey)
	if decryptedMessage == message {
		test.Errorf("One decrypts different ciphertexts and gets equal messages")
	}
}

func TestIncorrectDecryptionOnDifferentKeys(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	_, publicKey := keypair.GenerateKeypair()
	anotherPrivateKey, _ := keypair.GenerateKeypair()
	cipherText := encryption.Encrypt(message, publicKey)
	decryptedMessage := encryption.Decrypt(cipherText, anotherPrivateKey)
	if decryptedMessage == message {
		test.Errorf("One decrypts ciphertext by another private key and gets equal messages")
	}
}

func TestCorrectEncryptionAndDecryptionOnBlock(test *testing.T) {
	message := "ZK-STARK has big impact on StarkNet"
	privateKey, publicKey := keypair.GenerateKeypair()
	cipherText := encryption.Encrypt(message, publicKey)
	decryptedMessage := encryption.Decrypt(cipherText, privateKey)
	if decryptedMessage != message {
		test.Errorf("One encrypts and decrypts short message incorrectly")
	}
}

func TestCorrectEncryptionAndDecryptionOnBlocks(test *testing.T) {
	message := "StarkNet is an open-source, decentralized platform for building scalable " +
		"and secure applications on Ethereum. It is designed to provide high " +
		"throughput, low-cost transactions, and strong privacy guarantees " +
		"for smart contract execution. StarkNet achieves these goals " +
		"by utilizing a technology called zk-rollups, which allows " +
		"for off-chain execution of computations while maintaining " +
		"the security and trustlessness of the Ethereum blockchain. StarkNet " +
		"operates as a Layer 2 solution, meaning it operates on top of " +
		"the Ethereum mainnet, leveraging its security and decentralization. " +
		"It uses Zero-Knowledge Proofs to bundle and validate multiple " +
		"transactions off-chain, compressing them into a single proof that is then " +
		"submitted to the Ethereum mainnet for verification. This approach significantly " +
		"reduces the transaction fees and congestion on the mainnet while maintaining the " +
		"security and trust of Ethereum's consensus mechanism. StarkNet has the " +
		"potential to greatly enhance the scalability of decentralized applications " +
		"on Ethereum, enabling a wide range of use cases. By leveraging off-chain " +
		"computation and the security of the Ethereum mainnet, StarkNet aims to provide " +
		"a powerful infrastructure for building scalable and efficient " +
		"blockchain applications."
	privateKey, publicKey := keypair.GenerateKeypair()
	cipherText := encryption.Encrypt(message, publicKey)
	decryptedMessage := encryption.Decrypt(cipherText, privateKey)
	if decryptedMessage != message {
		test.Errorf("One encrypts and decrypts large message incorrectly")
	}
}
