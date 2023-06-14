package test

import (
	"ElGamal_Cryptosystem/pkg/encryption"
	"testing"
)

func TestMinusOperation(test *testing.T) {
	expectedResult := 5 - 3
	actualResult := encryption.Minus(5, 3)
	if expectedResult != actualResult {
		test.Errorf("Некоректна різниця чисел 5 і 3: %d", actualResult)
	}
}
