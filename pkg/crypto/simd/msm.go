package simd

import (
	"fmt"
	"math/big"
	"runtime"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// OptimizationLevel defines the level of optimization to use
type OptimizationLevel int

const (
	// OptimizationNone uses the standard implementation without SIMD
	OptimizationNone OptimizationLevel = iota
	
	// OptimizationAVX2 uses AVX2 instructions for optimization
	OptimizationAVX2
	
	// OptimizationAVX512 uses AVX512 instructions for optimization
	OptimizationAVX512
	
	// OptimizationNEON uses NEON instructions for optimization
	OptimizationNEON
	
	// OptimizationAuto selects the best available optimization
	OptimizationAuto
)

// MultiScalarMulG1 performs optimized multi-scalar multiplication for G1 points
// using SIMD instructions when available
func MultiScalarMulG1(points []bls12381.G1Affine, scalars []*big.Int, level OptimizationLevel) (bls12381.G1Affine, error) {
	if len(points) != len(scalars) {
		return bls12381.G1Affine{}, fmt.Errorf("number of points and scalars must match")
	}
	
	// Early return for empty input
	if len(points) == 0 {
		return bls12381.G1Affine{}, nil
	}
	
	// Convert big.Int scalars to fr.Element
	frScalars, err := convertScalars(scalars)
	if err != nil {
		return bls12381.G1Affine{}, fmt.Errorf("failed to convert scalars: %w", err)
	}
	
	// Determine optimization level to use
	optLevel := level
	if optLevel == OptimizationAuto {
		optLevel = determineOptimization()
	}
	
	// Use the appropriate implementation based on the optimization level
	switch optLevel {
	case OptimizationAVX2:
		if HasAVX2() {
			return MultiScalarMulG1AVX2(points, frScalars)
		}
		// Fall back to standard implementation
	case OptimizationAVX512:
		if HasAVX512() {
			return MultiScalarMulG1AVX512(points, frScalars)
		}
		// Fall back to AVX2 if available
		if HasAVX2() {
			return MultiScalarMulG1AVX2(points, frScalars)
		}
		// Fall back to standard implementation
	case OptimizationNEON:
		if HasNeon() {
			return MultiScalarMulG1NEON(points, frScalars)
		}
		// Fall back to standard implementation
	}
	
	// Standard implementation (no SIMD)
	var result bls12381.G1Jac
	result.MultiExp(points, frScalars, bls12381.MultiExpConfig{})
	
	var resultAffine bls12381.G1Affine
	resultAffine.FromJacobian(&result)
	
	return resultAffine, nil
}

// determineOptimization automatically determines the best optimization level
// based on the CPU architecture and available instructions
func determineOptimization() OptimizationLevel {
	// Check CPU architecture
	switch runtime.GOARCH {
	case "amd64":
		// Check for AVX512 support
		if HasAVX512() {
			return OptimizationAVX512
		}
		// Check for AVX2 support
		if HasAVX2() {
			return OptimizationAVX2
		}
	case "arm64":
		// Check for NEON support (always available on arm64)
		if HasNeon() {
			return OptimizationNEON
		}
	}
	
	// No optimizations available
	return OptimizationNone
}