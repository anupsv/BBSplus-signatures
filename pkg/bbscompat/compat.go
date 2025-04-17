// Package bbscompat provides compatibility with the original bbs package
// to ease migration to the new package structure.
//
// This package re-exports types and functions from the core package with
// the same names as the original bbs package, allowing for gradual migration.
//
// Example usage:
//
//     // Old code:
//     import "github.com/asv/bbs/bbs"
//     keyPair, _ := bbs.GenerateKeyPair(5, nil)
//
//     // New code with compatibility layer:
//     import "github.com/asv/bbs/pkg/bbscompat"
//     keyPair, _ := bbscompat.GenerateKeyPair(5, nil)
//
// It is recommended to eventually migrate to the new package structure
// for better organization and access to new features.
package bbscompat

import (
	"io"
	"math/big"

	"github.com/asv/bbs/pkg/core"
)

// Re-export types from core package
type (
	// KeyPair represents a BBS+ key pair
	KeyPair = core.KeyPair
	
	// PrivateKey represents a BBS+ private key
	PrivateKey = core.PrivateKey
	
	// PublicKey represents a BBS+ public key
	PublicKey = core.PublicKey
	
	// Signature represents a BBS+ signature
	Signature = core.Signature
	
	// ProofOfKnowledge represents a BBS+ selective disclosure proof
	ProofOfKnowledge = core.ProofOfKnowledge
)

// Re-export functions from core package

// GenerateKeyPair creates a new BBS+ key pair for the given number of messages
func GenerateKeyPair(messageCount int, rng io.Reader) (*KeyPair, error) {
	return core.GenerateKeyPair(messageCount, rng)
}

// DerivePublicKey derives a public key from a private key
func DerivePublicKey(privateKey *big.Int, messageCount int) (*PublicKey, error) {
	return core.DerivePublicKey(privateKey, messageCount)
}

// Sign creates a BBS+ signature on the given messages using the provided key pair
func Sign(privateKey *PrivateKey, publicKey *PublicKey, messages []*big.Int, header []byte) (*Signature, error) {
	return core.Sign(privateKey, publicKey, messages, header)
}

// Verify checks if a BBS+ signature is valid for the given messages and public key
func Verify(publicKey *PublicKey, signature *Signature, messages []*big.Int, header []byte) error {
	return core.Verify(publicKey, signature, messages, header)
}

// CreateProof generates a selective disclosure proof for the given messages
func CreateProof(
	publicKey *PublicKey,
	signature *Signature,
	messages []*big.Int,
	disclosedIndices []int,
	header []byte,
) (*ProofOfKnowledge, map[int]*big.Int, error) {
	return core.CreateProof(publicKey, signature, messages, disclosedIndices, header)
}

// VerifyProof checks if a selective disclosure proof is valid
func VerifyProof(
	publicKey *PublicKey,
	proof *ProofOfKnowledge,
	disclosedMessages map[int]*big.Int,
	header []byte,
) error {
	return core.VerifyProof(publicKey, proof, disclosedMessages, header)
}

// BatchVerifyProofs verifies multiple proofs in a batch for improved performance
func BatchVerifyProofs(
	keys []*PublicKey,
	proofs []*ProofOfKnowledge,
	disclosedMessagesList []map[int]*big.Int,
	headers [][]byte,
) error {
	return core.BatchVerifyProofs(keys, proofs, disclosedMessagesList, headers)
}