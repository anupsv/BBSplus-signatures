// Package core provides the main functionality of the BBS+ signature scheme.
//
// It includes key generation, signing, verification, and proof creation/verification
// operations. This package is the main entry point for applications using the BBS+ library.
//
// Basic usage:
//
//     // Generate a key pair for 5 messages
//     keyPair, err := core.GenerateKeyPair(5, nil)
//
//     // Sign messages
//     signature, err := core.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
//
//     // Verify signature
//     err = core.Verify(keyPair.PublicKey, signature, messages, nil)
//
//     // Create selective disclosure proof
//     proof, disclosedMsgs, err := core.CreateProof(keyPair.PublicKey, signature, messages, indices, nil)
//
//     // Verify proof
//     err = core.VerifyProof(keyPair.PublicKey, proof, disclosedMsgs, nil)
//
// The core package leverages the crypto, proof, and utils packages internally
// but presents a simplified API for most common operations.
package core

// Version information
const (
	// Major version component
	VersionMajor = 1
	// Minor version component
	VersionMinor = 0
	// Patch version component
	VersionPatch = 0
)