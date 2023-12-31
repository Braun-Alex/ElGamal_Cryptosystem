package signature

import (
	"crypto/rand"
	"github.com/Braun-Alex/ElGamal_Cryptosystem/pkg/keypair"
	"golang.org/x/crypto/sha3"
	"math/big"
)

func Sign(message string, privateKey *big.Int) (*big.Int, *big.Int) {
	// Converting of hash of message to decimal big number
	buffer := new(big.Int)
	messageHash := sha3.Sum512([]byte(message))
	hashDecimal := new(big.Int).SetBytes(messageHash[:])
	// Decremented module = p - 1
	decrementedModule := new(big.Int).Sub(keypair.P, big.NewInt(1))
	// Generating of session key from [0; p-1)
	k, err := rand.Int(rand.Reader, decrementedModule)
	// Checking for error and that session key must be not 0 or 1
	if err != nil || k.Cmp(big.NewInt(1)) <= 0 {
		panic("Session key could not be generated")
	}
	for buffer.GCD(nil, nil, k, decrementedModule).Cmp(big.NewInt(1)) != 0 {
		// Generating of session key from [0; p-1)
		k, err = rand.Int(rand.Reader, decrementedModule)
		// Checking for error and that session key must be not 0 or 1
		if err != nil || k.Cmp(big.NewInt(1)) <= 0 {
			panic("Session key could not be generated")
		}
	}
	r, s := new(big.Int), new(big.Int)
	// Generating of component r = g^k (mod p)
	r.Exp(keypair.G, k, keypair.P)
	// Generating of component s = (hashM - privateKey * r) * k^(-1) (mod p)
	buffer.Mul(privateKey, r)
	buffer.Sub(hashDecimal, buffer)
	k.ModInverse(k, decrementedModule)
	s.Mul(buffer, k)
	s.Mod(s, decrementedModule)
	return r, s
}

func Verify(message string, publicKey, r, s *big.Int) bool {
	buffer := new(big.Int)
	// Checking 0 < r < p
	if r.Cmp(big.NewInt(0)) != 1 || r.Cmp(keypair.P) != -1 {
		return false
	}
	// Checking 0 < s < p - 1
	if s.Cmp(big.NewInt(0)) != 1 || s.Cmp(buffer.Sub(keypair.P, big.NewInt(1))) != -1 {
		return false
	}
	// Converting of hash of message to decimal big number
	messageHash := sha3.Sum512([]byte(message))
	hashDecimal := new(big.Int).SetBytes(messageHash[:])
	v1, v2 := new(big.Int), new(big.Int)
	// Computing v1 = publicKey^r * r^s (mod p)
	v1.Exp(publicKey, r, keypair.P)
	buffer.Exp(r, s, keypair.P)
	v1.Mul(v1, buffer)
	v1.Mod(v1, keypair.P)
	// Computing v2 = g^m (mod p)
	v2.Exp(keypair.G, hashDecimal, keypair.P)
	// Signature is valid if publicKey^r * r^s == g^m (mod p)
	return v1.Cmp(v2) == 0
}
