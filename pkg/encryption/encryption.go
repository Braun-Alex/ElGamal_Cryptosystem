package encryption

import (
	"ElGamal_Cryptosystem/pkg/keypair"
	"crypto/rand"
	"math/big"
)

func Encrypt(message string, publicKey *big.Int) []*big.Int {
	dataBytes := []byte(message)
	// p is 4096-bit prime number, but for security reasons block size is 2048 bits
	const blockSize = 256
	// Rounds to encrypt each block of data
	var rounds int
	if len(dataBytes)%blockSize == 0 {
		rounds = len(dataBytes) / blockSize
	} else {
		rounds = len(dataBytes)/blockSize + 1
	}
	dataBlock, buffer := new(big.Int), new(big.Int)
	var i int
	// Decremented module = p - 1
	decrementedModule := new(big.Int).Sub(keypair.P, big.NewInt(1))
	// Slice with ciphertext pairs (x, y) for each block
	cipherText := make([]*big.Int, 0)
	for i = 0; i < rounds-1; i++ {
		// Converting of data block to number
		dataBlock.SetBytes(dataBytes[i*blockSize : (i+1)*blockSize])
		// Generating of session key from [0; p-1)
		k, err := rand.Int(rand.Reader, decrementedModule)
		// Checking for error and that session key must be not 0 or 1
		if err != nil || k.Cmp(big.NewInt(1)) <= 0 {
			panic("Session key could not be generated")
		}
		// For session key must be GCD(k, p-1) = 1
		for buffer.GCD(nil, nil, k, decrementedModule).Cmp(big.NewInt(1)) != 0 {
			// Generating of session key from [0; p-1)
			k, err = rand.Int(rand.Reader, decrementedModule)
			// Checking for error and that session key must be not 0 or 1
			if err != nil || k.Cmp(big.NewInt(1)) <= 0 {
				panic("Session key could not be generated")
			}
		}
		// Computing x = g^k (mod p)
		x := new(big.Int).Exp(keypair.G, k, keypair.P)
		// Computing publicKey^k * blockM (mod p)
		y := new(big.Int).Exp(publicKey, k, keypair.P)
		y.Mul(y, dataBlock)
		y.Mod(y, keypair.P)
		// Inserting of ciphertext pair (x, y) for current block
		cipherText = append(cipherText, x, y)
	}
	// Encrypting the last block that may be less or equal 256 bytes
	if len(dataBytes[i*blockSize:]) != 0 {
		dataBlock.SetBytes(dataBytes[i*blockSize:])
		// Generating of session key from [0; p-1)
		k, err := rand.Int(rand.Reader, decrementedModule)
		// Checking for error and that session key must be not 0 or 1
		if err != nil || k.Cmp(big.NewInt(1)) <= 0 {
			panic("Session key could not be generated")
		}
		// For session key must be GCD(k, p-1) = 1
		for buffer.GCD(nil, nil, k, decrementedModule).Cmp(big.NewInt(1)) != 0 {
			// Generating of session key from [0; p-1)
			k, err = rand.Int(rand.Reader, decrementedModule)
			// Checking for error and that session key must be not 0 or 1
			if err != nil || k.Cmp(big.NewInt(1)) <= 0 {
				panic("Session key could not be generated")
			}
		}
		// Computing x = g^k (mod p)
		x := new(big.Int).Exp(keypair.G, k, keypair.P)
		// Computing publicKey^k * blockM (mod p)
		y := new(big.Int).Exp(publicKey, k, keypair.P)
		y.Mul(y, dataBlock)
		y.Mod(y, keypair.P)
		// Inserting of ciphertext pair (x, y) for the last block
		cipherText = append(cipherText, x, y)
	}
	return cipherText
}

func Decrypt(cipherText []*big.Int, privateKey *big.Int) string {
	var message string
	// Decrypting of each ciphertext pair (x, y) for each block
	for i := 0; i < len(cipherText); i += 2 {
		dataBlock := new(big.Int)
		// Computing decryptedBlockM = y * x^(p - 1 - privateKey) (mod p)
		buffer := new(big.Int).Sub(keypair.P, big.NewInt(1))
		buffer.Sub(buffer, privateKey)
		dataBlock.Exp(cipherText[i], buffer, keypair.P)
		dataBlock.Mul(dataBlock, cipherText[i+1])
		dataBlock.Mod(dataBlock, keypair.P)
		// Converting of decrypted block data to bytes and inserting it to message
		message += string(dataBlock.Bytes())
	}
	return message
}
