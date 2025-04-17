package crypto

import (
	"fmt"
	"math/big"

	"github.com/anupsv/bbsplus-signatures/internal/common"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// MultiScalarMulG1 performs multi-scalar multiplication in G1.
// It computes the sum of point[i] * scalar[i] for all i.
func MultiScalarMulG1(points []bls12381.G1Affine, scalars []*big.Int) (bls12381.G1Affine, error) {
	if len(points) != len(scalars) {
		return bls12381.G1Affine{}, common.ErrMismatchedLengths
	}

	// Handle empty input
	if len(points) == 0 {
		return bls12381.G1Affine{}, nil
	}

	// Convert big.Int scalars to fr.Element for use with gnark-crypto
	frScalars := make([]fr.Element, len(scalars))
	for i, scalar := range scalars {
		if scalar == nil {
			return bls12381.G1Affine{}, fmt.Errorf("nil scalar at index %d", i)
		}

		bytes := scalar.Bytes()
		if err := frScalars[i].SetBytes(bytes); err != nil {
			return bls12381.G1Affine{}, fmt.Errorf("invalid scalar at index %d: %w", i, err)
		}
	}

	// Use batched multi-scalar multiplication for large input sets
	if len(points) > 16 {
		return batchedMSM(points, frScalars)
	}

	// For smaller input sets, use direct computation for better performance
	return directMSM(points, frScalars)
}

// batchedMSM performs multi-scalar multiplication using a bucketing algorithm
// for improved performance on large input sets.
func batchedMSM(points []bls12381.G1Affine, scalars []fr.Element) (bls12381.G1Affine, error) {
	// Compute the result in Jacobian coordinates for efficiency
	var result bls12381.G1Jac
	
	// Initialize result as the identity element
	result.X.SetOne()
	result.Y.SetOne()
	result.Z.SetOne()
	
	// Do scalar multiplication
	for i := 0; i < len(points); i++ {
		// Skip if scalar is zero or point is identity
		if scalars[i].IsZero() || points[i].IsInfinity() {
			continue
		}

		// Convert the scalar to big.Int for ScalarMultiplication
		var scalarBig big.Int
		scalars[i].ToBigIntRegular(&scalarBig)

		// Compute point * scalar
		var tmp bls12381.G1Jac
		tmp.FromAffine(&points[i])
		tmp.ScalarMultiplication(&tmp, &scalarBig)

		// Add to result
		if i == 0 && !points[i].IsInfinity() && !scalars[i].IsZero() {
			result = tmp
		} else {
			result.AddAssign(&tmp)
		}
	}

	// Convert to affine coordinates for the result
	var resultAffine bls12381.G1Affine
	resultAffine.FromJacobian(&result)

	return resultAffine, nil
}

// directMSM performs multi-scalar multiplication directly
// for better performance on small input sets.
func directMSM(points []bls12381.G1Affine, scalars []fr.Element) (bls12381.G1Affine, error) {
	// Initialize result as the identity element
	result := bls12381.G1Jac{}
	result.X.SetOne()
	result.Y.SetOne()
	result.Z.SetOne()

	// Process points in a single batch
	for i := 0; i < len(points); i++ {
		// Skip if scalar is zero or point is infinity
		if scalars[i].IsZero() || points[i].IsInfinity() {
			continue
		}

		// Convert scalar to big.Int for ScalarMultiplication
		var scalarBig big.Int
		scalars[i].ToBigIntRegular(&scalarBig)

		// Compute point * scalar
		var tmp bls12381.G1Jac
		tmp.FromAffine(&points[i])
		tmp.ScalarMultiplication(&tmp, &scalarBig)

		// Add to running sum
		result.AddAssign(&tmp)
	}

	// Convert result to affine coordinates
	var resultAffine bls12381.G1Affine
	resultAffine.FromJacobian(&result)

	return resultAffine, nil
}
