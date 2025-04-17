package bbs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// HierarchicalKeyDerivation enables creating derived keys from a master key
// This is useful for domain-specific and application-specific key generation
// without having to create and manage multiple independent keys
type HierarchicalKeyDerivation struct {
	masterKey *PrivateKey
}

// NewHierarchicalKeyDerivation creates a new hierarchical key derivation instance
func NewHierarchicalKeyDerivation(masterKey *PrivateKey) *HierarchicalKeyDerivation {
	return &HierarchicalKeyDerivation{
		masterKey: masterKey,
	}
}

// DeriveKey derives a child key from the master key using a derivation path
// The path consists of uint32 indices that determine the derivation path
// Similar to BIP32 but adapted for BBS+ signatures
func (hkd *HierarchicalKeyDerivation) DeriveKey(path []uint32) (*PrivateKey, error) {
	// Start with the master key
	key := new(big.Int).Set(hkd.masterKey.X)
	
	// HMAC-SHA256 for the key derivation function
	for _, index := range path {
		// Convert index to bytes
		indexBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(indexBytes, index)
		
		// Create input data for the KDF
		data := append(key.Bytes(), indexBytes...)
		
		// Use HMAC-SHA256 as the derivation function
		h := hmac.New(sha256.New, []byte("BBS_KEY_DERIVATION"))
		h.Write(data)
		digest := h.Sum(nil)
		
		// Convert to scalar and add to current key
		childComponent := new(big.Int).SetBytes(digest)
		childComponent.Mod(childComponent, Order)
		
		// Generate new key as parent + H(parent, index)
		key.Add(key, childComponent)
		key.Mod(key, Order)
	}
	
	// Create private key from derived scalar
	return &PrivateKey{X: key}, nil
}

// KeyRotation facilitates the rotation of keys while maintaining relationships
// between old and new keys, allowing for verification of signatures made with previous keys
type KeyRotation struct {
	currentKey *KeyPair
	history    []*KeyPair
	metadata   map[string]string
}

// NewKeyRotation creates a new key rotation instance
func NewKeyRotation(initialKey *KeyPair) *KeyRotation {
	return &KeyRotation{
		currentKey: initialKey,
		history:    []*KeyPair{initialKey},
		metadata:   make(map[string]string),
	}
}

// RotateKey generates a new key and adds the current key to history
func (kr *KeyRotation) RotateKey(rng io.Reader, messageCount int) error {
	// Generate a new key pair
	newKeyPair, err := GenerateKeyPair(messageCount, rng)
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}
	
	// Add current key to history
	kr.history = append(kr.history, kr.currentKey)
	
	// Update current key
	kr.currentKey = newKeyPair
	
	// Add rotation metadata
	kr.metadata[fmt.Sprintf("rotation_%d", len(kr.history))] = fmt.Sprintf("%d", messageCount)
	
	return nil
}

// GetCurrentKey returns the current key pair
func (kr *KeyRotation) GetCurrentKey() *KeyPair {
	return kr.currentKey
}

// GetKeyHistory returns the history of key pairs
func (kr *KeyRotation) GetKeyHistory() []*KeyPair {
	return kr.history
}

// GetKeyAtIndex returns the key pair at the specific history index
// Index 0 is the oldest key, higher indices are newer keys
func (kr *KeyRotation) GetKeyAtIndex(index int) (*KeyPair, error) {
	if index < 0 || index >= len(kr.history) {
		return nil, fmt.Errorf("invalid key history index: %d", index)
	}
	return kr.history[index], nil
}

// ThresholdKey represents a key that requires t-of-n participants to sign
type ThresholdKey struct {
	PublicKey    *PublicKey   // The combined public key
	Threshold    int          // Number of shares needed (t)
	TotalShares  int          // Total number of shares (n)
	MessageCount int          // Number of messages supported
}

// KeyShare represents a share of a threshold key
type KeyShare struct {
	Index      int          // Index of this share (1-based)
	Share      *big.Int     // The share value
	PublicKey  *PublicKey   // The combined public key (same for all shares)
	Commitment bls12381.G1Affine  // Commitment to this share for verification
}

// ThresholdSignature represents a threshold signature
type ThresholdSignature struct {
	Signature  *Signature
	Signers    []int
}

// GenerateThresholdKey creates a t-of-n threshold key
// Returns the threshold key setup and n key shares
func GenerateThresholdKey(t, n, messageCount int, rng io.Reader) (*ThresholdKey, []*KeyShare, error) {
	if t <= 0 || n <= 0 || t > n {
		return nil, nil, fmt.Errorf("invalid threshold parameters: t=%d, n=%d", t, n)
	}
	
	// Generate a random polynomial of degree t-1
	// f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
	// where a_0 is the secret key
	coefficients := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		coeff, err := RandomScalar(rng)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate coefficient: %w", err)
		}
		coefficients[i] = coeff
	}
	
	// The secret key is the constant coefficient a_0
	secretKey := &PrivateKey{X: coefficients[0]}
	
	// Generate the corresponding public key
	generators := GenerateGenerators(messageCount + 2)
	// Get the standard generator for G2
	_, _, _, g2Gen := bls12381.Generators()
	g2 := new(bls12381.G2Affine)
	*g2 = g2Gen
	
	// In a production implementation, we should hash to curve with proper domain separation
	// For now, we'll use the standard generator as a fallback
	if g2.IsInfinity() {
		return nil, nil, ErrInvalidGenerator
	}
	
	// Calculate W = g2 ^ x
	wJac := bls12381.G2Jac{}
	wJac.FromAffine(g2)
	wJac.ScalarMultiplication(&wJac, secretKey.X)
	w := g2JacToAffine(wJac)
	
	// Construct the public key
	// Get the standard generator for G1
	_, _, g1Gen, _ := bls12381.Generators()
	g1 := new(bls12381.G1Affine)
	*g1 = g1Gen
	
	// In a production implementation, we should hash to curve with proper domain separation
	// For now, we'll use the standard generator as a fallback
	if g1.IsInfinity() {
		return nil, nil, ErrInvalidGenerator
	}
	
	publicKey := &PublicKey{
		G1:           *g1,
		G2:           *g2,
		W:            w,
		H:            generators,
		MessageCount: messageCount,
	}
	
	// Create the threshold key struct
	thresholdKey := &ThresholdKey{
		PublicKey:    publicKey,
		Threshold:    t,
		TotalShares:  n,
		MessageCount: messageCount,
	}
	
	// Generate key shares for each participant (Shamir Secret Sharing)
	shares := make([]*KeyShare, n)
	for i := 1; i <= n; i++ {
		// Evaluate the polynomial at point i: f(i)
		// f(i) = a_0 + a_1*i + a_2*i^2 + ... + a_{t-1}*i^{t-1}
		x := big.NewInt(int64(i))
		value := new(big.Int).Set(coefficients[0])
		
		for j := 1; j < t; j++ {
			term := new(big.Int).SetInt64(1)
			for k := 0; k < j; k++ {
				term.Mul(term, x)
				term.Mod(term, Order)
			}
			
			term.Mul(term, coefficients[j])
			term.Mod(term, Order)
			
			value.Add(value, term)
			value.Mod(value, Order)
		}
		
		// Create commitment to the share for verification
		commitmentJac := bls12381.G1Jac{}
		commitmentJac.FromAffine(g1)
		commitmentJac.ScalarMultiplication(&commitmentJac, value)
		commitment := g1JacToAffine(commitmentJac)
		
		shares[i-1] = &KeyShare{
			Index:      i,
			Share:      value,
			PublicKey:  publicKey,
			Commitment: commitment,
		}
	}
	
	return thresholdKey, shares, nil
}

// ThresholdSign creates a signature using t key shares
func ThresholdSign(shares []*KeyShare, messages []*big.Int, header []byte) (*ThresholdSignature, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}
	
	publicKey := shares[0].PublicKey
	messageCount := publicKey.MessageCount
	
	if len(messages) != messageCount {
		return nil, ErrInvalidMessageCount
	}
	
	// Collect the indices of the signers
	indices := make([]int, len(shares))
	for i, share := range shares {
		indices[i] = share.Index
	}
	
	// Calculate the Lagrange coefficients for interpolation
	lagrangeCoeffs := calculateLagrangeCoefficients(indices)
	
	// Compute the combined private key using Lagrange interpolation
	combinedKey := big.NewInt(0)
	for i, share := range shares {
		term := new(big.Int).Mul(share.Share, lagrangeCoeffs[i])
		term.Mod(term, Order)
		combinedKey.Add(combinedKey, term)
		combinedKey.Mod(combinedKey, Order)
	}
	
	// Create a temporary private key from the combined shares
	tempPrivKey := &PrivateKey{X: combinedKey}
	
	// Create the signature using the standard signing function
	signature, err := Sign(tempPrivKey, publicKey, messages, header)
	if err != nil {
		return nil, fmt.Errorf("failed to create threshold signature: %w", err)
	}
	
	return &ThresholdSignature{
		Signature: signature,
		Signers:   indices,
	}, nil
}

// VerifyThresholdSignature verifies a threshold signature
func VerifyThresholdSignature(thresholdKey *ThresholdKey, thresholdSig *ThresholdSignature, messages []*big.Int, header []byte) error {
	// Use the standard verification function
	return Verify(thresholdKey.PublicKey, thresholdSig.Signature, messages, header)
}

// Helper function to calculate Lagrange coefficients for interpolation
func calculateLagrangeCoefficients(indices []int) []*big.Int {
	n := len(indices)
	coeffs := make([]*big.Int, n)
	
	for i := 0; i < n; i++ {
		idx := big.NewInt(int64(indices[i]))
		
		// Calculate the Lagrange basis polynomial at x=0
		// L_i(0) = ∏_{j≠i} (0 - x_j) / (x_i - x_j)
		num := big.NewInt(1)
		den := big.NewInt(1)
		
		for j := 0; j < n; j++ {
			if j == i {
				continue
			}
			
			// 0 - x_j
			xj := big.NewInt(int64(indices[j]))
			zero_minus_xj := new(big.Int).Neg(xj)
			zero_minus_xj.Mod(zero_minus_xj, Order)
			
			// x_i - x_j
			xi_minus_xj := new(big.Int).Sub(idx, xj)
			xi_minus_xj.Mod(xi_minus_xj, Order)
			
			// Update numerator and denominator
			num.Mul(num, zero_minus_xj)
			num.Mod(num, Order)
			
			den.Mul(den, xi_minus_xj)
			den.Mod(den, Order)
		}
		
		// Calculate coefficient as num/den (mod Order)
		denInv := ConstantTimeModInverse(den, Order)
		coeffs[i] = new(big.Int).Mul(num, denInv)
		coeffs[i].Mod(coeffs[i], Order)
	}
	
	return coeffs
}