package test

import (
	"ElGamal_Cryptosystem/pkg/signature"
	"testing"
)

func TestPlusOperation(test *testing.T) {
	expectedResult := 5 + 3
	actualResult := signature.Plus(5, 3)
	if expectedResult != actualResult {
		test.Errorf("Некоректна різниця чисел 5 і 3: %d", actualResult)
	}
}
