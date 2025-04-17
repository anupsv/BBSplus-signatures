#!/bin/bash
# Script to reorganize the BBS+ codebase

set -e

echo "Starting codebase reorganization..."

# Create the new directory structure
echo "Creating new directory structure..."
mkdir -p pkg/core pkg/crypto pkg/credential pkg/proof pkg/utils pkg/wasm
mkdir -p internal/pool internal/common

# Move core functionality
echo "Moving core functionality..."
cp bbs/*.go pkg/core/
grep -l "package bbs" pkg/core/*.go | xargs sed -i'' -e 's/package bbs/package core/g'

# Create crypto package
echo "Creating crypto package..."
cp bbs/utils.go pkg/crypto/utils.go
sed -i'' -e 's/package bbs/package crypto/g' pkg/crypto/utils.go

# Create utils package
echo "Creating utils package..."
cp bbs/utils.go pkg/utils/utils.go
sed -i'' -e 's/package bbs/package utils/g' pkg/utils/utils.go

# Move object pooling to internal
echo "Moving object pooling to internal..."
cp bbs/pool.go internal/pool/pool.go
sed -i'' -e 's/package bbs/package pool/g' internal/pool/pool.go

# Create common package
echo "Creating common package..."
cat > internal/common/errors.go << EOF
package common

import "errors"

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
EOF

# Update imports
echo "Updating imports..."
find pkg internal -name "*.go" -type f -exec sed -i'' \
    -e 's,github.com/anupsv/bbsplus-signatures/bbs/bbs,github.com/anupsv/bbsplus-signatures/bbs/pkg/core,g' \
    -e 's,import ",import "github.com/anupsv/bbsplus-signatures/bbs/internal/common\nimport ",g' \
    {} \;

# Create migration helper
echo "Creating migration helper..."
cat > pkg/bbscompat/compat.go << EOF
// Package bbscompat provides compatibility with the original bbs package
// to ease migration to the new package structure.
package bbscompat

import (
	"github.com/anupsv/bbsplus-signatures/bbs/pkg/core"
)

// Re-export types from core package
type (
	KeyPair = core.KeyPair
	PrivateKey = core.PrivateKey
	PublicKey = core.PublicKey
	Signature = core.Signature
	ProofOfKnowledge = core.ProofOfKnowledge
)

// Re-export functions from core package
var (
	GenerateKeyPair = core.GenerateKeyPair
	DerivePublicKey = core.DerivePublicKey
	Sign = core.Sign
	Verify = core.Verify
	CreateProof = core.CreateProof
	VerifyProof = core.VerifyProof
	BatchVerifyProofs = core.BatchVerifyProofs
)
EOF

echo "Reorganization complete!"