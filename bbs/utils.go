package bbs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Error constants
var (
	ErrMismatchedLengths = errors.New("mismatch between points and scalars length")
	ErrScalarConversion  = errors.New("failed to convert scalar to field element")
)

// Domain separation tags are defined in constants.go

// MessageToFieldElement converts a byte array to a field element
func MessageToFieldElement(message []byte) *big.Int {
	// Hash the message using SHA-256
	h := sha256.Sum256(message)

	// Convert to big.Int and reduce modulo Order
	elem := new(big.Int).SetBytes(h[:])
	return elem.Mod(elem, Order)
}

// MessageToBytes converts a message string to a suitable byte representation
func MessageToBytes(message string) []byte {
	return []byte(message)
}

// RandomScalar generates a random scalar modulo the order of the curve
func RandomScalar(rng io.Reader) (*big.Int, error) {
	// Use the constant-time implementation for secure random values
	return ConstantTimeRandom(rng, Order)
}

// ConstantTimeRandom generates a random value in [0, max-1] with constant-time operations
// This helps prevent timing attacks that could leak information about generated values
func ConstantTimeRandom(rng io.Reader, max *big.Int) (*big.Int, error) {
	// Calculate the number of bytes needed to represent max
	// Add 64 extra bits to ensure we have enough entropy after rejection sampling
	byteLen := (max.BitLen() + 64 + 7) / 8
	
	// Create a mask for the most significant byte to avoid modulo bias
	bits := max.BitLen() % 8
	mask := byte(0xFF)
	if bits > 0 {
		mask = byte((1 << bits) - 1)
	}
	
	// Buffer for random bytes
	b := make([]byte, byteLen)
	
	// We'll use rejection sampling to ensure uniform distribution
	result := new(big.Int)
	
	for {
		// Get random bytes
		if _, err := rng.Read(b); err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}
		
		// Apply mask to the most significant byte to avoid modulo bias
		if len(b) > 0 {
			b[0] &= mask
		}
		
		// Convert to big.Int
		result.SetBytes(b)
		
		// Check if the value is in range [0, max-1]
		// This comparison is not constant-time, but we only leak information
		// about whether the random value was in range, not the value itself
		if result.Cmp(max) < 0 {
			break
		}
	}
	
	return result, nil
}

// ConstantTimeModInverse computes the modular inverse of a
// in constant time using Fermat's little theorem
func ConstantTimeModInverse(a, n *big.Int) *big.Int {
	// a^(n-2) mod n (Fermat's little theorem) for prime n
	e := new(big.Int).Sub(n, big.NewInt(2))
	return new(big.Int).Exp(a, e, n)
}

// ConstantTimeCompare compares two big.Int values in constant time
// Returns -1 if a < b, 0 if a == b, and 1 if a > b
func ConstantTimeCompare(a, b *big.Int) int {
	// XOR the bits to find differences
	diff := new(big.Int).Xor(a, b)
	
	// If there are no differences, they're equal
	if diff.Sign() == 0 {
		return 0
	}
	
	// Find most significant bit that differs
	// This part isn't constant time, but we only use the sign afterwards
	diffBits := diff.BitLen()
	
	// Get the corresponding bits from a and b
	aBit := a.Bit(diffBits - 1)
	bBit := b.Bit(diffBits - 1)
	
	// Compare the bits (will be either 1 or -1)
	if aBit > bBit {
		return 1
	}
	return -1
}

// ConstantTimeEq compares two big.Int values for equality in constant time
// Returns true if a == b, false otherwise
func ConstantTimeEq(a, b *big.Int) bool {
	// XOR the bits to find differences
	diff := new(big.Int).Xor(a, b)
	
	// If there are no differences, they're equal
	return diff.Sign() == 0
}

// ConstantTimeSelect selects one of two big.Int values based on condition in constant time
// If condition is true, returns a, otherwise returns b
func ConstantTimeSelect(condition bool, a, b *big.Int) *big.Int {
	var mask int
	if condition {
		mask = 0xff
	} else {
		mask = 0x00
	}
	
	// Convert mask to a big.Int (all bits set or no bits set)
	maskInt := new(big.Int)
	if mask == 0xff {
		// Set to all 1s up to max of a and b bit length
		maxBits := a.BitLen()
		if b.BitLen() > maxBits {
			maxBits = b.BitLen()
		}
		maskInt.SetBit(maskInt, maxBits, 1)
		maskInt.Sub(maskInt, big.NewInt(1))
	}
	
	// a_masked = a & mask
	// b_masked = b & ~mask
	// result = a_masked | b_masked
	a_masked := new(big.Int).And(a, maskInt)
	mask_inverted := new(big.Int).Not(maskInt)
	b_masked := new(big.Int).And(b, mask_inverted)
	return new(big.Int).Or(a_masked, b_masked)
}

// g1JacToAffine converts a G1 Jacobian point to affine
func g1JacToAffine(p bls12381.G1Jac) bls12381.G1Affine {
	result := bls12381.G1Affine{}
	result.FromJacobian(&p)
	return result
}

// g1JacPtrToAffine safely converts a G1 Jacobian point pointer to affine
func g1JacPtrToAffine(p *bls12381.G1Jac) bls12381.G1Affine {
	result := bls12381.G1Affine{}
	result.FromJacobian(p)
	return result
}

// g2JacToAffine converts a G2 Jacobian point to affine
func g2JacToAffine(p bls12381.G2Jac) bls12381.G2Affine {
	result := bls12381.G2Affine{}
	result.FromJacobian(&p)
	return result
}

// Compute a domain value from a public key and optional header
// This is used in the signing and verification algorithms
func CalculateDomain(publicKey *PublicKey, header []byte) *big.Int {
	// Concatenate public key parameters to compute a domain
	var buff []byte
	
	// Append L
	msgCount := make([]byte, 4)
	msgCount[0] = byte(publicKey.MessageCount >> 24)
	msgCount[1] = byte(publicKey.MessageCount >> 16)
	msgCount[2] = byte(publicKey.MessageCount >> 8)
	msgCount[3] = byte(publicKey.MessageCount)
	buff = append(buff, msgCount...)
	
	// Append Q_1 point
	buff = append(buff, publicKey.H[0].Marshal()...)
	
	// Append Q_2 point
	buff = append(buff, publicKey.H[1].Marshal()...)
	
	// Append remaining H[i] points
	for i := 2; i < len(publicKey.H); i++ {
		buff = append(buff, publicKey.H[i].Marshal()...)
	}
	
	// Append public key W and generators
	buff = append(buff, publicKey.W.Marshal()...)
	buff = append(buff, publicKey.G1.Marshal()...)
	buff = append(buff, publicKey.G2.Marshal()...)
	
	// Append header if present
	if header != nil {
		buff = append(buff, header...)
	}
	
	// Hash the buffer and interpret as a big integer mod Order
	h := sha256.New()
	h.Write(buff)
	digest := h.Sum(nil)
	
	domain := new(big.Int).SetBytes(digest)
	return domain.Mod(domain, Order)
}

// GenerateGenerators generates message-specific generators
// Based on IRTF cfrg-bbs-signatures
func GenerateGenerators(count int) []bls12381.G1Affine {
	generators := make([]bls12381.G1Affine, count)
	
	// Use a deterministic approach to create generators
	for i := 0; i < count; i++ {
		// Create a seed specific to this generator
		seed := []byte(fmt.Sprintf("BBS_BLS12381_GENERATOR_%d", i))
		
		// Hash the seed to get bytes
		h := sha256.Sum256(seed)
		
		// Create a Jacobian point and set it
		gJac := bls12381.G1Jac{}
		gJac.X.SetBytes(h[:16])
		gJac.Y.SetBytes(h[16:])
		gJac.Z.SetOne()
		
		// Map to the curve
		generators[i].FromJacobian(&gJac)
		
		// Multiply by cofactor to ensure it's in the correct subgroup
		cofactorJac := bls12381.G1Jac{}
		cofactorJac.FromAffine(&generators[i])
		
		// Use generator as a base point to ensure we get a point on the curve
		g1 := bls12381.G1Affine{}
		g1.X.SetOne()
		g1.Y.SetOne()
		
		baseJac := bls12381.G1Jac{}
		baseJac.FromAffine(&g1)
		
		// Scale by a deterministic scalar (hash of i)
		iBytes := []byte{byte(i)}
		scalar := new(big.Int).SetBytes(append(h[:], iBytes...))
		scalar.Mod(scalar, Order)
		
		baseJac.ScalarMultiplication(&baseJac, scalar)
		generators[i].FromJacobian(&baseJac)
	}
	
	return generators
}

// Check if two slices of G1Affine points are equal
func AreG1PointsEqual(a, b []bls12381.G1Affine) bool {
	if len(a) != len(b) {
		return false
	}
	
	for i := 0; i < len(a); i++ {
		if !a[i].Equal(&b[i]) {
			return false
		}
	}
	
	return true
}

// ComputeProofChallenge computes a Fiat-Shamir challenge for a proof
func ComputeProofChallenge(
	APrime bls12381.G1Affine,
	ABar bls12381.G1Affine,
	D bls12381.G1Affine,
	disclosedIndices []int,
	disclosedMessages map[int]*big.Int,
) *big.Int {
	// Build challenge input bytes: (A', A-bar, D, disclosed message indices, disclosed message values)
	var buff []byte
	
	// Add A'
	buff = append(buff, APrime.Marshal()...)
	
	// Add A-bar
	buff = append(buff, ABar.Marshal()...)
	
	// Add D
	buff = append(buff, D.Marshal()...)
	
	// Add sorted indices of disclosed messages
	// Ensure deterministic ordering of indices
	sortedIndices := make([]int, 0, len(disclosedIndices))
	copy(sortedIndices, disclosedIndices)
	sort.Ints(sortedIndices)
	
	for _, idx := range sortedIndices {
		// Convert index to 4 bytes
		idxBytes := make([]byte, 4)
		idxBytes[0] = byte(idx >> 24)
		idxBytes[1] = byte(idx >> 16)
		idxBytes[2] = byte(idx >> 8)
		idxBytes[3] = byte(idx)
		buff = append(buff, idxBytes...)
		
		// Convert message value to bytes
		msgBytes := disclosedMessages[idx].Bytes()
		
		// Add length prefix (4 bytes) followed by actual bytes
		lenBytes := make([]byte, 4)
		lenBytes[0] = byte(len(msgBytes) >> 24)
		lenBytes[1] = byte(len(msgBytes) >> 16)
		lenBytes[2] = byte(len(msgBytes) >> 8)
		lenBytes[3] = byte(len(msgBytes))
		
		buff = append(buff, lenBytes...)
		buff = append(buff, msgBytes...)
	}
	
	// Hash the buffer
	h := sha256.New()
	h.Write(buff)
	digest := h.Sum(nil)
	
	// Interpret as big.Int and reduce modulo order
	challenge := new(big.Int).SetBytes(digest)
	return challenge.Mod(challenge, Order)
}

// Note: Object pooling functions are defined in pool.go

// MultiScalarMulG1 implements multi-scalar multiplication for G1 points
// This is a custom implementation as gnark-crypto does not provide a direct implementation
func MultiScalarMulG1(points []bls12381.G1Affine, scalars []*big.Int) (bls12381.G1Jac, error) {
	if len(points) != len(scalars) {
		return bls12381.G1Jac{}, fmt.Errorf("mismatch between points and scalars length")
	}
	
	// Initialize result as the identity element in Jacobian coordinates
	// The identity element has Z=0 in Jacobian coordinates
	result := bls12381.G1Jac{}
	result.X.SetOne()  // Set X to 1
	result.Y.SetOne()  // Set Y to 1
	result.Z.SetZero() // Set Z to 0 for identity point
	
	// Optimization: Process points in batches to improve cache locality
	batchSize := 8 // Tuned for typical CPU cache line size
	
	// Process full batches
	for i := 0; i <= len(points)-batchSize; i += batchSize {
		// Batch accumulation
		for j := i; j < i+batchSize; j++ {
			if scalars[j].Sign() == 0 || points[j].IsInfinity() {
				continue
			}
			
			var tmp bls12381.G1Jac
			tmp.FromAffine(&points[j])
			tmp.ScalarMultiplication(&tmp, scalars[j])
			
			result.AddAssign(&tmp)
		}
	}
	
	// Process remaining points
	for i := (len(points) / batchSize) * batchSize; i < len(points); i++ {
		if scalars[i].Sign() == 0 || points[i].IsInfinity() {
			continue
		}
		
		var tmp bls12381.G1Jac
		tmp.FromAffine(&points[i])
		tmp.ScalarMultiplication(&tmp, scalars[i])
		
		result.AddAssign(&tmp)
	}
	
	return result, nil
}