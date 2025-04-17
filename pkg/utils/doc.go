// Package utils provides utility functions for the BBS+ library.
//
// These utilities include:
// - Constant-time operations for secure cryptographic operations
// - Type conversions and helpers
// - Serialization/deserialization utilities
// - Memory management helpers
//
// This package is designed to be used by other packages in the BBS+ library
// and typically doesn't need to be used directly by applications.
//
// Example usage:
//
//     // Constant-time modular inverse
//     inverse := utils.ConstantTimeModInverse(value, modulus)
//     
//     // Secure random scalar
//     scalar, err := utils.RandomScalar(rand.Reader)
//     
//     // Message conversion
//     fieldElement := utils.MessageToFieldElement(messageBytes)
//
// Most of these utilities are internal implementation details that support
// the higher-level functionality in the core and proof packages.
package utils

import (
	"math/big"
)

// Constants used in utility functions
var (
	// Zero is a pre-allocated big.Int with value 0
	Zero = big.NewInt(0)
	
	// One is a pre-allocated big.Int with value 1
	One = big.NewInt(1)
	
	// Two is a pre-allocated big.Int with value 2
	Two = big.NewInt(2)
)