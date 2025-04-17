package core

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// KeyPair represents a BBS+ key pair
type KeyPair struct {
	// PrivateKey is the private key component
	PrivateKey *PrivateKey
	
	// PublicKey is the public key component
	PublicKey *PublicKey
	
	// MessageCount is the number of messages this key pair supports
	MessageCount int
}

// PrivateKey represents a BBS+ private key
type PrivateKey struct {
	// Value is the private key scalar value
	Value *big.Int
}

// PublicKey represents a BBS+ public key
type PublicKey struct {
	// W is the public key point (g2^x where x is the private key)
	W bls12381.G2Affine
	
	// H is the array of generator points for messages
	H []bls12381.G1Affine
	
	// H0 is a generator point for blinding factors
	H0 bls12381.G1Affine
	
	// G1 is the base generator point for G1
	G1 bls12381.G1Affine
	
	// G2 is the base generator point for G2
	G2 bls12381.G2Affine
	
	// MessageCount is the number of messages this key supports
	MessageCount int
}

// Signature represents a BBS+ signature
type Signature struct {
	// A is the signature point
	A bls12381.G1Affine
	
	// E is the signature blinding factor
	E *big.Int
	
	// S is the signature randomness
	S *big.Int
}

// ProofOfKnowledge represents a BBS+ selective disclosure proof
type ProofOfKnowledge struct {
	// APrime is the modified signature point
	APrime bls12381.G1Affine
	
	// ABar is a commitment to the signature
	ABar bls12381.G1Affine
	
	// D is a commitment to the blinding factors
	D bls12381.G1Affine
	
	// C is the Fiat-Shamir challenge
	C *big.Int
	
	// EHat is the blinded signature blinding factor
	EHat *big.Int
	
	// SHat is the blinded signature randomness
	SHat *big.Int
	
	// MHat contains the blinded undisclosed messages
	MHat []*big.Int
	
	// RHat contains the blinded message randomness
	RHat []*big.Int
}

// SignOptions contains options for the Sign operation
type SignOptions struct {
	// DeterministicSignature enables deterministic signature generation
	// (primarily for testing)
	DeterministicSignature bool
	
	// Blinding factors for signature generation (if nil, random values are used)
	BlindingFactors *SignatureBlindingFactors
}

// SignatureBlindingFactors contains blinding factors for signature generation
type SignatureBlindingFactors struct {
	// E is the signature blinding factor
	E *big.Int
	
	// S is the signature randomness
	S *big.Int
}

// ProofOptions contains options for proof creation
type ProofOptions struct {
	// DeterministicProof enables deterministic proof generation
	// (primarily for testing)
	DeterministicProof bool
	
	// RevealAll forces all messages to be revealed
	RevealAll bool
	
	// QuickVerify optimizes proof for faster verification
	// (may make proofs larger)
	QuickVerify bool
}

// VerifyOptions contains options for signature verification
type VerifyOptions struct {
	// Batch enables batch verification when multiple signatures
	// are being verified
	Batch bool
	
	// QuickVerify uses optimizations that may sacrifice some security
	// for improved performance
	QuickVerify bool
}