package bbs

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math/big"
	
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// DeterministicSignature generates a deterministic signature following 
// a methodology similar to RFC 6979 (deterministic ECDSA)
// This prevents signature malleability and removes the need for a secure random
// number generator during signing
func DeterministicSign(
	sk *PrivateKey,
	pk *PublicKey,
	messages []*big.Int,
	header []byte,
	extraEntropy []byte, // Optional additional entropy
) (*Signature, error) {
	// Validate inputs
	if len(messages) != pk.MessageCount {
		return nil, ErrInvalidMessageCount
	}

	// Calculate the domain
	domain := CalculateDomain(pk, header)

	// Initial data to derive randomness
	data := make([]byte, 0, 100)
	
	// Private key
	data = append(data, sk.X.Bytes()...)
	
	// Domain
	data = append(data, domain.Bytes()...)
	
	// Messages
	for _, m := range messages {
		data = append(data, m.Bytes()...)
	}
	
	// Add header if present
	if header != nil {
		data = append(data, header...)
	}
	
	// Add extra entropy if present
	if extraEntropy != nil {
		data = append(data, extraEntropy...)
	}
	
	// Initial hash
	hash := sha256.Sum256(data)
	
	// Generate deterministic values e and s
	e := deterministicScalar(hash[:], []byte("BBS_PLUS_DETERMINISTIC_E"))
	s := deterministicScalar(hash[:], []byte("BBS_PLUS_DETERMINISTIC_S"))
	
	// Compute B = H₀ + H₁·domain + sum_{j=1}^L H_{j+1}·m_j
	Bjac := bls12381.G1Jac{}
	
	// Start with H₀ (Q1)
	Bjac.FromAffine(&pk.H[0])
	
	// Add H₁·domain (Q2·domain)
	h1DomJac := bls12381.G1Jac{}
	h1DomJac.FromAffine(&pk.H[1])
	h1DomJac.ScalarMultiplication(&h1DomJac, domain)
	Bjac.AddAssign(&h1DomJac)
	
	// Add sum_{j=1}^L H_{j+1}·m_j
	for i, m := range messages {
		hiJac := bls12381.G1Jac{}
		hiJac.FromAffine(&pk.H[i+2]) // +2 for Q1, Q2
		hiJac.ScalarMultiplication(&hiJac, m)
		Bjac.AddAssign(&hiJac)
	}
	
	B := g1JacToAffine(Bjac)
	
	// Compute A = g1 · (1 / (x + e)) · B^(-s)
	
	// Calculate 1/(x + e)
	denominator := new(big.Int).Add(sk.X, e)
	invDenom := ConstantTimeModInverse(denominator, Order)
	
	// Calculate g1 · (1 / (x + e))
	g1InvDenomJac := bls12381.G1Jac{}
	g1InvDenomJac.FromAffine(&pk.G1)
	g1InvDenomJac.ScalarMultiplication(&g1InvDenomJac, invDenom)
	
	// Calculate B^(-s)
	negS := new(big.Int).Neg(s)
	negS.Mod(negS, Order)
	BnegSJac := bls12381.G1Jac{}
	BnegSJac.FromAffine(&B)
	BnegSJac.ScalarMultiplication(&BnegSJac, negS)
	
	// Combine to get A
	AJac := bls12381.G1Jac{}
	AJac.Set(&g1InvDenomJac)
	AJac.AddAssign(&BnegSJac)
	A := g1JacToAffine(AJac)
	
	return &Signature{
		A: A,
		E: e,
		S: s,
	}, nil
}

// deterministicScalar generates a deterministic scalar in [1, Order-1]
// based on the input seed and label
func deterministicScalar(seed []byte, label []byte) *big.Int {
	// Create a HMAC-SHA256 instance with the seed as the key
	h := hmac.New(sha256.New, seed)
	
	// Initialize data with a counter
	counter := byte(1)
	
	// Generate enough bytes for a uniformly distributed scalar
	byteLength := (Order.BitLen() + 7) / 8
	result := make([]byte, 0, byteLength+8) // Extra room for safety
	
	// K is the intermediate HMAC key
	K := seed
	
	// V is all 1s initially (as per RFC 6979)
	V := make([]byte, 32)
	for i := range V {
		V[i] = 0x01
	}
	
	// Label is added to ensure domain separation
	h.Reset()
	h.Write(V)
	h.Write([]byte{0x00})
	h.Write(K)
	h.Write(label)
	K = h.Sum(nil)
	h.Reset()
	
	// Update V
	h.Write(V)
	V = h.Sum(nil)
	h.Reset()
	
	// Main generation loop
	for len(result) < byteLength {
		h.Write(V)
		h.Write([]byte{counter})
		result = append(result, h.Sum(nil)...)
		counter++
		h.Reset()
	}
	
	// Convert to big.Int and ensure it's in the range [1, Order-1]
	scalar := new(big.Int).SetBytes(result[:byteLength])
	
	// Make sure the scalar is in [1, Order-1]
	scalar.Mod(scalar, Order)
	if scalar.Sign() == 0 {
		scalar.SetInt64(1) // Ensure non-zero
	}
	
	return scalar
}

// ExtendProofDeterministic extends an existing proof by revealing additional attributes
// It allows to update a proof to disclose more attributes without requiring the original signature
func ExtendProofDeterministic(
	proof *ProofOfKnowledge,
	originalDisclosed map[int]*big.Int,
	newlyDisclosedIndices []int,
	secretMessages map[int]*big.Int,
	pk *PublicKey,
) (*ProofOfKnowledge, map[int]*big.Int, error) {
	// Validate inputs
	for _, idx := range newlyDisclosedIndices {
		if idx < 0 || idx >= pk.MessageCount {
			return nil, nil, fmt.Errorf("invalid newly disclosed index: %d", idx)
		}
		
		// Check if this index was already disclosed
		if _, disclosed := originalDisclosed[idx]; disclosed {
			return nil, nil, fmt.Errorf("index %d is already disclosed", idx)
		}
		
		// Check if we have the secret message for this index
		if _, ok := secretMessages[idx]; !ok {
			return nil, nil, fmt.Errorf("missing secret message for index %d", idx)
		}
		
		// Check if the index is in the MHat map of the proof
		if _, ok := proof.MHat[idx]; !ok {
			return nil, nil, fmt.Errorf("index %d not found in proof", idx)
		}
	}
	
	// Create a new map of disclosed indices
	newDisclosed := make(map[int]*big.Int)
	for idx, value := range originalDisclosed {
		newDisclosed[idx] = value
	}
	
	// Add newly disclosed messages
	for _, idx := range newlyDisclosedIndices {
		newDisclosed[idx] = secretMessages[idx]
	}
	
	// Create a new MHat map from the old one
	newMHat := make(map[int]*big.Int)
	for idx, value := range proof.MHat {
		newMHat[idx] = value
	}
	
	// Remove newly disclosed messages from MHat
	for _, idx := range newlyDisclosedIndices {
		delete(newMHat, idx)
	}
	
	// Get all indices for the new disclosure
	disclosedIndices := make([]int, 0, len(newDisclosed))
	for idx := range newDisclosed {
		disclosedIndices = append(disclosedIndices, idx)
	}
	
	// Recompute the challenge
	newC := ComputeProofChallenge(
		proof.APrime,
		proof.ABar,
		proof.D,
		disclosedIndices,
		newDisclosed,
	)
	
	// For each newly disclosed message, update the D value
	// D' = D - sum_i(H_i^(m_i*c))
	DprimeJac := bls12381.G1Jac{}
	DprimeJac.FromAffine(&proof.D)
	
	for _, idx := range newlyDisclosedIndices {
		// m_i * c
		msgC := new(big.Int).Mul(secretMessages[idx], proof.C)
		msgC.Mod(msgC, Order)
		
		// Negate it for subtraction
		negMsgC := new(big.Int).Neg(msgC)
		negMsgC.Mod(negMsgC, Order)
		
		// H_i^(-m_i*c)
		hiNegMsgCJac := bls12381.G1Jac{}
		hiNegMsgCJac.FromAffine(&pk.H[idx+2]) // +2 for Q1, Q2
		hiNegMsgCJac.ScalarMultiplication(&hiNegMsgCJac, negMsgC)
		
		// Add to D'
		DprimeJac.AddAssign(&hiNegMsgCJac)
	}
	
	// Convert to affine
	Dprime := g1JacToAffine(DprimeJac)
	
	// Create the extended proof
	extendedProof := &ProofOfKnowledge{
		APrime: proof.APrime,
		ABar:   proof.ABar,
		D:      Dprime,
		C:      newC,
		EHat:   proof.EHat,
		SHat:   proof.SHat,
		MHat:   newMHat,
	}
	
	return extendedProof, newDisclosed, nil
}