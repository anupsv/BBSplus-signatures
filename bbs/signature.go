package bbs

import (
	"crypto/rand"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Sign creates a BBS+ signature for the given messages
// Implementation follows the IRTF cfrg-bbs-signatures specification
func Sign(sk *PrivateKey, pk *PublicKey, messages []*big.Int, header []byte) (*Signature, error) {
	// Validate inputs
	if len(messages) != pk.MessageCount {
		return nil, ErrInvalidMessageCount
	}
	
	// Calculate domain value
	domain := CalculateDomain(pk, header)
	
	// Generate random values e, s from Zp
	e, err := RandomScalar(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value e: %w", err)
	}

	s, err := RandomScalar(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value s: %w", err)
	}

	// Compute B = P1 * (1) + Q1 * (s) + Q2 * (domain) + H1 * (m1) + ... + HL * (mL)
	// In our implementation:
	// - P1 is pk.G1
	// - Q1 is pk.H[0]
	// - Q2 is pk.H[1]
	// - H1...HL are pk.H[2...]
	
	// Start with g1 (P1)
	BJac := bls12381.G1Jac{}
	BJac.FromAffine(&pk.G1)

	// Add Q1 * s
	q1sJac := bls12381.G1Jac{}
	q1sJac.FromAffine(&pk.H[0])
	q1sJac.ScalarMultiplication(&q1sJac, s)
	BJac.AddAssign(&q1sJac)
	
	// Add Q2 * domain
	q2domJac := bls12381.G1Jac{}
	q2domJac.FromAffine(&pk.H[1])
	q2domJac.ScalarMultiplication(&q2domJac, domain)
	BJac.AddAssign(&q2domJac)

	// Add each H_i * m_i
	for i, m := range messages {
		hiJac := bls12381.G1Jac{}
		hiJac.FromAffine(&pk.H[i+2]) // +2 because H[0] is Q1, H[1] is Q2
		hiJac.ScalarMultiplication(&hiJac, m)
		BJac.AddAssign(&hiJac)
	}
	
	// Convert to affine
	B := g1JacToAffine(BJac)

	// Compute A = B^(1/(x+e))
	// First, compute 1/(x+e)
	xPlusE := new(big.Int).Add(sk.X, e)
	inv := new(big.Int).ModInverse(xPlusE, Order)
	if inv == nil {
		return nil, fmt.Errorf("failed to compute modular inverse")
	}

	// Then, compute A = B^(1/(x+e))
	AJac := bls12381.G1Jac{}
	AJac.FromAffine(&B)
	AJac.ScalarMultiplication(&AJac, inv)
	
	// Convert to affine
	A := g1JacToAffine(AJac)

	return &Signature{
		A: A,
		E: e,
		S: s,
	}, nil
}

// Verify checks if a signature is valid for the given messages
// Implementation follows the IRTF cfrg-bbs-signatures specification
func Verify(pk *PublicKey, signature *Signature, messages []*big.Int, header []byte) error {
	// Validate inputs
	if len(messages) != pk.MessageCount {
		return ErrInvalidMessageCount
	}

	// Calculate domain value
	domain := CalculateDomain(pk, header)
	
	// Recompute B = P1 * (1) + Q1 * (s) + Q2 * (domain) + H1 * (m1) + ... + HL * (mL)
	// Start with g1 (P1)
	BJac := bls12381.G1Jac{}
	BJac.FromAffine(&pk.G1)

	// Add Q1 * s
	q1sJac := bls12381.G1Jac{}
	q1sJac.FromAffine(&pk.H[0])
	q1sJac.ScalarMultiplication(&q1sJac, signature.S)
	BJac.AddAssign(&q1sJac)
	
	// Add Q2 * domain
	q2domJac := bls12381.G1Jac{}
	q2domJac.FromAffine(&pk.H[1])
	q2domJac.ScalarMultiplication(&q2domJac, domain)
	BJac.AddAssign(&q2domJac)

	// Add each H_i * m_i
	for i, m := range messages {
		hiJac := bls12381.G1Jac{}
		hiJac.FromAffine(&pk.H[i+2]) // +2 because H[0] is Q1, H[1] is Q2
		hiJac.ScalarMultiplication(&hiJac, m)
		BJac.AddAssign(&hiJac)
	}
	
	// Convert to affine
	B := g1JacToAffine(BJac)

	// Compute w * g2^e = W + P2 * e
	// Start with w (same as W)
	wg2eJac := bls12381.G2Jac{}
	wg2eJac.FromAffine(&pk.W)

	// Add g2^e (P2 * e)
	g2eJac := bls12381.G2Jac{}
	g2eJac.FromAffine(&pk.G2)
	g2eJac.ScalarMultiplication(&g2eJac, signature.E)
	wg2eJac.AddAssign(&g2eJac)
	
	// Convert to affine
	wg2e := g2JacToAffine(wg2eJac)

	// Negate g2 for the second pairing
	negG2Jac := bls12381.G2Jac{}
	negG2Jac.FromAffine(&pk.G2)
	negG2Jac.Neg(&negG2Jac)
	negG2 := g2JacToAffine(negG2Jac)

	// Check e(A, W + P2*e) * e(B, -P2) = 1
	// This is equivalent to e(A, W + P2*e) = e(B, P2)
	pairingResult, err := bls12381.Pair(
		[]bls12381.G1Affine{signature.A, B},
		[]bls12381.G2Affine{wg2e, negG2},
	)
	if err != nil {
		return ErrPairingFailed
	}
	
	// Check if the pairing result is 1
	if !pairingResult.IsOne() {
		return ErrInvalidSignature
	}

	return nil
}

// SignWithCommitment creates a BBS+ signature with 'commit' messages
// where each message can be either a commitment or an actual message
func SignWithCommitment(
	sk *PrivateKey,
	pk *PublicKey,
	messages []*big.Int,
	commitments map[int]*big.Int,
	header []byte,
) (*Signature, error) {
	if len(messages) != pk.MessageCount {
		return nil, ErrInvalidMessageCount
	}
	
	// Create a copy of messages
	combinedMsgs := make([]*big.Int, len(messages))
	copy(combinedMsgs, messages)
	
	// Replace actual messages with commitments where applicable
	for idx, commit := range commitments {
		if idx < 0 || idx >= len(combinedMsgs) {
			return nil, fmt.Errorf("invalid commitment index: %d", idx)
		}
		combinedMsgs[idx] = commit
	}
	
	// Sign with the mixed messages
	return Sign(sk, pk, combinedMsgs, header)
}

// VerifyWithCommitment verifies a BBS+ signature with partial knowledge of messages
func VerifyWithCommitment(
	pk *PublicKey,
	signature *Signature,
	messages []*big.Int,
	commitIndices []int,
	header []byte,
) error {
	if len(messages) != pk.MessageCount {
		return ErrInvalidMessageCount
	}
	
	// Verify signature normally
	return Verify(pk, signature, messages, header)
}