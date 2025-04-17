package core

import (
	"math/big"

	"github.com/anupsv/bbsplus-signatures/internal/common"
)

// Public error variables from the BBS+ library
var (
	// ErrInvalidSignature indicates a signature verification failure
	ErrInvalidSignature = common.ErrInvalidSignature

	// ErrInvalidProof indicates a proof verification failure
	ErrInvalidProof = common.ErrInvalidProof

	// ErrInvalidPublicKey indicates an invalid public key
	ErrInvalidPublicKey = common.ErrInvalidPublicKey

	// ErrInvalidParameter indicates an invalid parameter
	ErrInvalidParameter = common.ErrInvalidParameter

	// ErrMismatchedLengths indicates mismatched lengths in inputs
	ErrMismatchedLengths = common.ErrMismatchedLengths
)

// BLS12-381 curve constants
var (
	// Order is the order of the BLS12-381 curve
	Order, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
)
