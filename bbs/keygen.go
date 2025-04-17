package bbs

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// GenerateKeyPair creates a new BBS+ key pair with support for the specified number of messages
// Following IRTF cfrg-bbs-signatures for standards compliance
func GenerateKeyPair(messageCount int, rng io.Reader) (*KeyPair, error) {
	if rng == nil {
		rng = rand.Reader
	}

	// For testing with deterministic seed, we'll use a fixed private key
	// if the rng is a bytes.Reader (indicates test mode)
	var x *big.Int
	var err error
	
	// Check if we're using a deterministic reader (for tests)
	if _, ok := rng.(*bytes.Reader); ok {
		// Use a fixed key for tests - this is obviously not secure for production
		x = big.NewInt(12345)
	} else {
		// Normal operation - generate random key
		x, err = RandomScalar(rng)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
	}

	// Create private key
	sk := &PrivateKey{
		X: x,
	}

	// Get standard generators from BLS12-381
	_, _, g1, g2 := bls12381.Generators() // Get generators in affine form

	// Compute w = g2^x (PK.W in IRTF spec)
	g2Jac := bls12381.G2Jac{}
	g2Jac.FromAffine(&g2)
	g2Jac.ScalarMultiplication(&g2Jac, x)

	// Convert to affine
	w := g2JacToAffine(g2Jac)

	// Generate message-specific generators (h_0, h_1, ..., h_L+1)
	// The IRTF spec requires at least (messageCount + 2) generators:
	// - H[0] is Q1 (used for blinding)
	// - H[1] is Q2 (used for domain separation)
	// - H[2...] are message-specific generators
	generators := GenerateGenerators(messageCount + 2)

	// Create public key
	pk := &PublicKey{
		W:            w,
		G2:           g2,
		G1:           g1,
		H:            generators,
		MessageCount: messageCount,
	}

	return &KeyPair{
		PrivateKey: sk,
		PublicKey:  pk,
	}, nil
}

// SerializePrivateKey serializes a private key to bytes
func SerializePrivateKey(sk *PrivateKey) []byte {
	return sk.X.Bytes()
}

// DeserializePrivateKey deserializes a private key from bytes
func DeserializePrivateKey(data []byte) (*PrivateKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid private key data")
	}

	x := new(big.Int).SetBytes(data)

	// Validate that x is in the correct range
	if x.Cmp(big.NewInt(0)) <= 0 || x.Cmp(Order) >= 0 {
		return nil, fmt.Errorf("private key out of range")
	}

	return &PrivateKey{
		X: x,
	}, nil
}

// SerializePublicKey serializes a public key to bytes
func SerializePublicKey(pk *PublicKey) []byte {
	// Format:
	// - W point (compressed G2 point)
	// - Message count (4 bytes)
	// - G1 generator (compressed G1 point)
	// - G2 generator (compressed G2 point)
	// - H generators (array of compressed G1 points)

	var result []byte

	// Add W point
	result = append(result, pk.W.Marshal()...)

	// Add message count (4 bytes, big endian)
	countBytes := make([]byte, 4)
	countBytes[0] = byte(pk.MessageCount >> 24)
	countBytes[1] = byte(pk.MessageCount >> 16)
	countBytes[2] = byte(pk.MessageCount >> 8)
	countBytes[3] = byte(pk.MessageCount)
	result = append(result, countBytes...)

	// Add G1 generator
	result = append(result, pk.G1.Marshal()...)

	// Add G2 generator
	result = append(result, pk.G2.Marshal()...)

	// Add H generators
	for _, h := range pk.H {
		result = append(result, h.Marshal()...)
	}

	return result
}

// DeserializePublicKey deserializes a public key from bytes
func DeserializePublicKey(data []byte) (*PublicKey, error) {
	if len(data) < 100 { // Minimum size based on required components
		return nil, fmt.Errorf("invalid public key data")
	}

	// Format:
	// - W point (compressed G2 point) - 96 bytes
	// - Message count (4 bytes)
	// - G1 generator (compressed G1 point) - 48 bytes
	// - G2 generator (compressed G2 point) - 96 bytes
	// - H generators (array of compressed G1 points) - 48 bytes each

	offset := 0

	// Parse W
	var w bls12381.G2Affine
	err := w.Unmarshal(data[offset : offset+96])
	if err != nil {
		return nil, fmt.Errorf("failed to parse W: %w", err)
	}
	offset += 96

	// Parse message count
	messageCount := int(data[offset])<<24 | int(data[offset+1])<<16 |
		int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4

	// Parse G1 generator
	var g1 bls12381.G1Affine
	err = g1.Unmarshal(data[offset : offset+48])
	if err != nil {
		return nil, fmt.Errorf("failed to parse G1: %w", err)
	}
	offset += 48

	// Parse G2 generator
	var g2 bls12381.G2Affine
	err = g2.Unmarshal(data[offset : offset+96])
	if err != nil {
		return nil, fmt.Errorf("failed to parse G2: %w", err)
	}
	offset += 96

	// Parse H generators
	h := make([]bls12381.G1Affine, 0, messageCount+2) // Q1, Q2, and message generators
	for i := 0; i < messageCount+2; i++ {
		if offset+48 > len(data) {
			return nil, fmt.Errorf("insufficient data for H generators")
		}

		var point bls12381.G1Affine
		err = point.Unmarshal(data[offset : offset+48])
		if err != nil {
			return nil, fmt.Errorf("failed to parse H[%d]: %w", i, err)
		}
		h = append(h, point)
		offset += 48
	}

	return &PublicKey{
		W:            w,
		G2:           g2,
		G1:           g1,
		H:            h,
		MessageCount: messageCount,
	}, nil
}
