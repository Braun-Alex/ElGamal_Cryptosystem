package main

import (
	"ElGamal_Cryptosystem/pkg/encryption"
	"ElGamal_Cryptosystem/pkg/signature"
	"fmt"
)

func main() {
	difference := encryption.Minus(5, 3)
	sum := signature.Plus(5, 3)
	fmt.Printf("Difference: %d, sum: %d", difference, sum)
}
