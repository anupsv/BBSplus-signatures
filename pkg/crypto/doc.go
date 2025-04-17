// Package crypto provides cryptographic primitives for the BBS+ signature scheme.
//
// It contains low-level cryptographic operations including:
// - Elliptic curve operations on BLS12-381
// - Multi-scalar multiplication
// - Pairing operations
// - Hashing to curve
//
// This package is used internally by the core package but can also be used
// directly for advanced use cases requiring finer control over cryptographic operations.
//
// Example usage:
//
//     // Multi-scalar multiplication
//     result, err := crypto.MultiScalarMulG1(points, scalars)
//
//     // Hash to G1
//     point, err := crypto.HashToG1(message, domainSeparationTag)
//
// Most applications will not need to use this package directly and should
// use the core package instead.
package crypto

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Domain separation tags
const (
	// DST_G1 is the domain separation tag for hashing to G1
	DST_G1 = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
	
	// DST_G2 is the domain separation tag for hashing to G2
	DST_G2 = "BBS_BLS12381G2_XMD:SHA-256_SSWU_RO_"
)