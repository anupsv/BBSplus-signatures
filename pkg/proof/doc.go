// Package proof provides functionality for creating and verifying BBS+ selective disclosure proofs.
//
// It focuses on the proof creation and verification aspects of the BBS+ signature scheme,
// offering more advanced proof operations than the core package. This includes:
// - Advanced proof creation with predicates
// - Batch proof verification
// - Proof customization options
// - Proof serialization/deserialization
//
// Example usage:
//
//     // Create a basic proof
//     proofBuilder := proof.NewBuilder()
//     proofBuilder.SetSignature(signature)
//     proofBuilder.SetMessages(messages)
//     proofBuilder.Disclose(0, 2) // Disclose messages at indices 0 and 2
//     p, disclosed, err := proofBuilder.Build()
//     
//     // Advanced proof with predicate
//     proofBuilder.AddPredicate(1, proof.PredicateGreaterThan, 18) // Age > 18
//     
//     // Verify a proof
//     verifier := proof.NewVerifier()
//     verifier.SetPublicKey(publicKey)
//     verifier.SetProof(p)
//     verifier.SetDisclosedMessages(disclosed)
//     err = verifier.Verify()
//
// For basic proof creation and verification, the core package provides simpler methods.
// This package is intended for more advanced use cases.
package proof

// Predicate types for proof creation
type PredicateType int

const (
	// PredicateEquals represents an equality predicate (value == x)
	PredicateEquals PredicateType = iota
	
	// PredicateGreaterThan represents a greater than predicate (value > x)
	PredicateGreaterThan
	
	// PredicateLessThan represents a less than predicate (value < x)
	PredicateLessThan
	
	// PredicateInRange represents a range predicate (min <= value <= max)
	PredicateInRange
	
	// PredicateNotEqual represents an inequality predicate (value != x)
	PredicateNotEqual
)