package bbs

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func TestMultiScalarMulWrapper(t *testing.T) {
	// Create test data
	point := bls12381.G1Affine{}
	point.X.SetString("1")
	point.Y.SetString("2")
	
	points := []bls12381.G1Affine{point}
	scalars := []*big.Int{big.NewInt(3)}
	
	// Test wrapper function
	result, err := multiScalarMulWrapper(points, scalars)
	
	// Just check that we get a valid result with no error
	if err != nil {
		t.Errorf("multiScalarMulWrapper returned error: %v", err)
	}
	
	if result == nil {
		t.Errorf("multiScalarMulWrapper returned nil result")
	}
}

func TestMapConversions(t *testing.T) {
	// Create test data
	boolMap := map[int]bool{
		1: true,
		2: false,
		3: true,
	}
	
	// Convert bool map to big.Int map
	bigIntMap := mapBoolToBigInt(boolMap)
	
	// Verify conversion
	if bigIntMap[1].Cmp(big.NewInt(1)) != 0 {
		t.Errorf("mapBoolToBigInt failed: expected 1, got %v", bigIntMap[1])
	}
	
	if bigIntMap[2].Cmp(big.NewInt(0)) != 0 {
		t.Errorf("mapBoolToBigInt failed: expected 0, got %v", bigIntMap[2])
	}
	
	// Convert back to bool map
	convertedBoolMap := mapBigIntToBool(bigIntMap)
	
	// Verify conversion
	if convertedBoolMap[1] != true {
		t.Errorf("mapBigIntToBool failed: expected true, got %v", convertedBoolMap[1])
	}
	
	if convertedBoolMap[2] != false {
		t.Errorf("mapBigIntToBool failed: expected false, got %v", convertedBoolMap[2])
	}
}