package signature

import (
	"crypto/rand"
	"golang.org/x/crypto/sha3"
	"math/big"
)

func Sign(message string, privateKey, p, g *big.Int) (r, s *big.Int) {
	// Converting hash of message to decimal big number
	buffer := new(big.Int)
	messageHash := sha3.New512()
	messageHash.Write([]byte(message))
	hashDecimal := new(big.Int)
	hashDecimal.SetBytes(messageHash.Sum(nil))
	// Decremented module = p - 1
	decrementedModule := buffer.Sub(p, big.NewInt(1))
	// Generation of session key
	k, err := rand.Int(rand.Reader, decrementedModule)
	if err != nil {
		panic("Parameter k could not be computed via signing")
	}
	// Generating of component r
	r = buffer.Exp(g, k, p)
	// Generating of component s
	buffer.Mul(privateKey, r)
	buffer.Sub(hashDecimal, buffer)
	k.ModInverse(k, decrementedModule)
	s = buffer.Mul(buffer, k)
	return
}

func Verify(message string, publicKey, r, s, p, g *big.Int) bool {
	buffer := new(big.Int)
	// Checking 0 < r < p
	if r.Cmp(big.NewInt(0)) != 1 || r.Cmp(p) != -1 {
		return false
	}
	// Checking 0 < s < p - 1
	if s.Cmp(big.NewInt(0)) != 1 || s.Cmp(buffer.Sub(p, big.NewInt(1))) != -1 {
		return false
	}
	// Converting hash of message to decimal big number
	messageHash := sha3.New512()
	messageHash.Write([]byte(message))
	hashDecimal := new(big.Int)
	hashDecimal.SetBytes(messageHash.Sum(nil))
	leftExpression, rightExpression := new(big.Int), new(big.Int)
	// Computing publicKey^r * r^s (mod p)
	leftExpression.Exp(publicKey, r, nil)
	buffer.Exp(r, s, nil)
	leftExpression.Mul(leftExpression, buffer)
	leftExpression.Mod(leftExpression, p)
	// Computing g^m (mod p)
	rightExpression.Exp(g, hashDecimal, p)
	// Signature is valid if publicKey^r * r^s = g^m (mod p)
	return leftExpression.Cmp(rightExpression) == 0
}
