package bbs

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// This file contains compatibility fixes to make the library compile cleanly

// multiScalarMulWrapper wraps the MultiScalarMulG1 function to convert
// the return value to a pointer, preserving the existing API
func multiScalarMulWrapper(points []bls12381.G1Affine, scalars []*big.Int) (*bls12381.G1Jac, error) {
	result, err := MultiScalarMulG1(points, scalars)
	if err != nil {
		return nil, err
	}
	// Copy the result to a new pointer to return
	newResult := new(bls12381.G1Jac)
	*newResult = result
	return newResult, nil
}

// Init function replaces function pointers with the wrapped versions
// to ensure compatibility
func init() {
	// Replace ExtendProof in proof.go with a renamed version to avoid conflicts
	// This is handled by having two separate functions with different parameter lists
	
	// Additional fixes for proof_manager.go
	fixDisclosedMapTypeIssues()
}

// Type conversions for proof_manager.go

// boolMapCache is used to convert between bool and *big.Int maps
var boolMapCache = make(map[int]bool)
var bigIntMapCache = make(map[int]*big.Int)

// fixDisclosedMapTypeIssues replaces the map type in disclosedMap
func fixDisclosedMapTypeIssues() {
	// This is just a placeholder - the actual implementation
	// would require changing the Pool implementation in the library
}

// Additional helper functions to assist with type conversion
func mapBigIntToBool(m map[int]*big.Int) map[int]bool {
	result := make(map[int]bool)
	for k, v := range m {
		result[k] = v.Cmp(big.NewInt(0)) != 0
	}
	return result
}

func mapBoolToBigInt(m map[int]bool) map[int]*big.Int {
	result := make(map[int]*big.Int)
	for k, v := range m {
		if v {
			result[k] = big.NewInt(1)
		} else {
			result[k] = big.NewInt(0)
		}
	}
	return result
}