package encryption

import (
	"ElGamal_Cryptosystem/pkg/keypair"
	"crypto/rand"
	"math/big"
)

func Encrypt(message string, publicKey *big.Int) []*big.Int {
	dataBytes := []byte(message)
	const maxBytes = 256
	blockSize := maxBytes
	var rounds int
	if len(dataBytes)%blockSize == 0 {
		rounds = len(dataBytes) / blockSize
	} else {
		rounds = len(dataBytes)/blockSize + 1
	}
	dataBlock, buffer := new(big.Int), new(big.Int)
	var i int
	decrementedModule := new(big.Int).Sub(keypair.P, big.NewInt(1))
	cipherText := make([]*big.Int, 0)
	for i = 0; i < rounds-1; i += blockSize {
		dataBlock.SetBytes(dataBytes[i : i+blockSize])
		k, err := rand.Int(rand.Reader, decrementedModule)
		if err != nil || k.Cmp(big.NewInt(0)) == 0 {
			panic("Session key could not be generated")
		}
		for buffer.GCD(nil, nil, k, decrementedModule).Cmp(big.NewInt(1)) != 0 {
			k, err = rand.Int(rand.Reader, decrementedModule)
			if err != nil || k.Cmp(big.NewInt(0)) == 0 {
				panic("Session key could not be generated")
			}
		}
		x := new(big.Int).Exp(keypair.G, k, keypair.P)
		y := new(big.Int).Exp(publicKey, k, nil)
		y.Mul(y, dataBlock)
		y.Mod(y, keypair.P)
		cipherText = append(cipherText, x, y)
	}
	dataBlock.SetBytes(dataBytes[i:])
	k, err := rand.Int(rand.Reader, decrementedModule)
	if err != nil || k.Cmp(big.NewInt(0)) == 0 {
		panic("Session key could not be generated")
	}
	for buffer.GCD(nil, nil, k, decrementedModule).Cmp(big.NewInt(1)) != 0 {
		k, err = rand.Int(rand.Reader, decrementedModule)
		if err != nil || k.Cmp(big.NewInt(0)) == 0 {
			panic("Session key could not be generated")
		}
	}
	x := new(big.Int).Exp(keypair.G, k, keypair.P)
	y := new(big.Int).Exp(publicKey, k, keypair.P)
	y.Mul(y, dataBlock)
	y.Mod(y, keypair.P)
	cipherText = append(cipherText, x, y)
	return cipherText
}

func Decrypt(cipherText []*big.Int, privateKey *big.Int) string {
	var message string
	for i := 0; i < len(cipherText); i += 2 {
		dataBlock := new(big.Int)
		buffer := new(big.Int).Sub(keypair.P, big.NewInt(1))
		buffer.Sub(buffer, privateKey)
		dataBlock.Exp(cipherText[i], buffer, keypair.P)
		dataBlock.Mul(dataBlock, cipherText[i+1])
		dataBlock.Mod(dataBlock, keypair.P)
		message += string(dataBlock.Bytes())
	}
	return message
}
