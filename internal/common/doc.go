// Package common provides shared functionality and constants used throughout the BBS+ library.
//
// This package includes:
// - Common error definitions
// - Shared constants
// - Internal helper functions
//
// This is an internal package not intended for direct use by applications.
// It supports the implementation of the public packages.
package common

import (
	"errors"
)

// Common errors used throughout the BBS+ library
var (
	// ErrInvalidSignature indicates a signature verification failure
	ErrInvalidSignature = errors.New("invalid signature")
	
	// ErrInvalidProof indicates a proof verification failure
	ErrInvalidProof = errors.New("invalid proof")
	
	// ErrInvalidPublicKey indicates an invalid public key
	ErrInvalidPublicKey = errors.New("invalid public key")
	
	// ErrInvalidParameter indicates an invalid parameter
	ErrInvalidParameter = errors.New("invalid parameter")
	
	// ErrMismatchedLengths indicates mismatched lengths in inputs
	ErrMismatchedLengths = errors.New("mismatched lengths")
)