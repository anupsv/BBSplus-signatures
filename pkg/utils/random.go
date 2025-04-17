package utils

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

// RandomScalar generates a random scalar in the range [1, order-1]
func RandomScalar(reader io.Reader) (*big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	
	// Get curve order
	order, _ := new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	
	// Generate a random integer in the range [1, order-1]
	// by generating a random value in [0, order-2] and adding 1
	max := new(big.Int).Sub(order, big.NewInt(1))
	n, err := rand.Int(reader, max)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value: %w", err)
	}
	
	// Add 1 to ensure the scalar is not zero
	n.Add(n, big.NewInt(1))
	
	return n, nil
}

// ConstantTimeRandom generates a random scalar using constant-time operations
// This is more secure for cryptographic applications where timing attacks are a concern
func ConstantTimeRandom(reader io.Reader, order *big.Int) (*big.Int, error) {
	// Generate extra bits to ensure uniformity
	bytes := make([]byte, 48) // 384 bits, well above the 256 bits needed
	
	if _, err := io.ReadFull(reader, bytes); err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}
	
	// Convert to big.Int and reduce modulo order
	n := new(big.Int).SetBytes(bytes)
	n.Mod(n, order)
	
	// Ensure non-zero
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	
	return n, nil
}