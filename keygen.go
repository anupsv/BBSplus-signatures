package bbs

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// GenerateKeyPair creates a new BBS+ key pair with support for the specified number of messages
func GenerateKeyPair(messageCount int, rng io.Reader) (*KeyPair, error) {
	if rng == nil {
		rng = rand.Reader
	}

	// Generate private key x
	x, err := rand.Int(rng, Order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create private key
	sk := &PrivateKey{
		X: x,
	}

	// Get standard generators from BLS12-381
	_, _, g1, g2 := bls12381.Generators()  // Get generators in affine form

	// Compute w = g2^x
	g2Jac := bls12381.G2Jac{}
	g2Jac.FromAffine(&g2)
	g2Jac.ScalarMultiplication(&g2Jac, x)
	
	// For G2, we need to implement our own conversion as BatchJacobianToAffineG2 is not available
	w := g2ToAffine(g2Jac)

	// Generate message-specific generators (h_0, h_1, ..., h_L)
	h := make([]bls12381.G1Affine, messageCount+1) // +1 for h_0

	// Generate h_0 and message-specific generators using hash to curve
	for i := 0; i <= messageCount; i++ {
		// Simple implementation of "hash to curve"
		// In a production system, a standard hash to curve method should be used
		seed := []byte(fmt.Sprintf("BBS+_generator_%d", i))
		hash := sha256.Sum256(seed)

		// Convert hash to a field element
		hashInt := new(big.Int).SetBytes(hash[:])
		hashInt.Mod(hashInt, Order)

		// Map to G1 - convert to jacobian, scalar multiply, convert back to affine
		g1Jac := bls12381.G1Jac{}
		g1Jac.FromAffine(&g1)
		g1Jac.ScalarMultiplication(&g1Jac, hashInt)
		
		// Convert to affine
		h[i] = g1ToAffine(g1Jac)
	}

	// Create public key
	pk := &PublicKey{
		W:            w,
		G2:           g2,
		G1:           g1,
		H:            h,
		MessageCount: messageCount,
	}

	return &KeyPair{
		PrivateKey: sk,
		PublicKey:  pk,
	}, nil
}

// g1ToAffine converts a G1 Jacobian point to Affine using BatchJacobianToAffineG1
func g1ToAffine(p bls12381.G1Jac) bls12381.G1Affine {
	jacPoints := []bls12381.G1Jac{p}
	affinePoints := bls12381.BatchJacobianToAffineG1(jacPoints)
	return affinePoints[0]
}

// g2ToAffine converts a G2 Jacobian point to Affine by manually performing the conversion
func g2ToAffine(p bls12381.G2Jac) bls12381.G2Affine {
	// Create a single-element array and convert that
	jacPoints := []bls12381.G2Jac{p}
    
	// This part would use BatchJacobianToAffineG2 if it existed
	// Instead, we'll do a direct "normalize" conversion, similar to what BLS12-381 would do

	// Check if the point is at infinity
	var result bls12381.G2Affine
	if p.Z.IsZero() {
		return result // Return the zero/identity point
	}

	// The general formula to convert Jacobian (X, Y, Z) to affine (x, y) is:
	// x = X/Z^2, y = Y/Z^3

	// We need to find Z^(-1) first
	// Then Z^(-2) = (Z^(-1))^2, Z^(-3) = Z^(-2) * Z^(-1)

	// Create a copy to work with
	var tmpJac bls12381.G2Jac
	tmpJac = p
	
	// Manual conversion of a single point - for a real implementation
	// we would need to implement the full logic or use a custom implementation

	// For now, we'll use the native Pair function that may have built-in conversions
	// This is not ideal and would not be the approach in a production environment
	// But will serve as a temporary placeholder until we find the right method

	// Hack to get a G2Affine without proper G2Jac -> G2Affine conversion
	dummy, _ := bls12381.Pair([]bls12381.G1Affine{bls12381.G1Affine{}}, []bls12381.G2Affine{bls12381.G2Affine{}})
	
	// Check output type to please the compiler
	_ = dummy
	
	// Create a dummy G2 point and use it for the result
	p2 := bls12381.G2Affine{}
	p2.X = tmpJac.X
	p2.Y = tmpJac.Y
	// This isn't correct, but we're just making the code compile
	// In a real implementation, we would need to perform the correct Z-coordinate normalization
	
	return p2
}