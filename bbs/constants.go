// Package bbs implements the BBS+ signature scheme based on the IRTF draft-irtf-cfrg-bbs-signatures
// Using BLS12-381 elliptic curve as the underlying pairing-friendly curve
package bbs

import (
	"errors"
	"math/big"
)

var (
	// ErrInvalidSignature is returned when a signature fails verification
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidMessageCount is returned when the number of messages doesn't match the key parameters
	ErrInvalidMessageCount = errors.New("invalid message count")

	// ErrInvalidProofData is returned when proof data cannot be deserialized
	ErrInvalidProofData = errors.New("invalid proof data")

	// ErrInvalidSignatureData is returned when signature data cannot be deserialized
	ErrInvalidSignatureData = errors.New("invalid signature data")

	// ErrPairingFailed is returned when a pairing computation fails
	ErrPairingFailed = errors.New("pairing computation failed")

	// ErrInvalidGenerator is returned when a generator is invalid
	ErrInvalidGenerator = errors.New("invalid generator")
	
	// ErrInvalidArrayLengths is returned when the lengths of input arrays don't match
	ErrInvalidArrayLengths = errors.New("mismatched input array lengths")

	// Order of the groups G1, G2, and GT for BLS12-381
	// BLS12-381 curve order: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
	Order, _ = new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	
	// Domain separation tags for hashing to curve
	DST_G1 = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
	DST_G2 = "BBS_BLS12381G2_XMD:SHA-256_SSWU_RO_"
)