# BBS+ Signatures API Documentation

Welcome to the API documentation for the BBS+ signatures library. This documentation provides comprehensive information about the library's APIs, usage patterns, and implementation details.

## Table of Contents

- [Introduction](#introduction)
- [Package Structure](#package-structure)
- [Core API](#core-api)
- [Credential Management](#credential-management)
- [Proof Operations](#proof-operations)
- [Cryptographic Primitives](#cryptographic-primitives)
- [Utilities](#utilities)
- [WebAssembly Integration](#webassembly-integration)
- [Examples](#examples)
- [Security Considerations](#security-considerations)

## Introduction

BBS+ is a pairing-based cryptographic signature scheme that allows for selective disclosure of signed messages. This library provides a comprehensive implementation of BBS+ signatures, with a focus on:

- Performance optimization
- Memory efficiency
- Security hardening
- Integration with credential systems

## Package Structure

The BBS+ library is organized into the following packages:

- `pkg/core`: Core BBS+ functionality
- `pkg/crypto`: Cryptographic primitives
- `pkg/credential`: Credential management
- `pkg/proof`: Proof generation and verification
- `pkg/utils`: Utility functions
- `pkg/wasm`: WebAssembly bindings
- `internal/common`: Common internal utilities
- `internal/pool`: Object pooling for memory optimization

## Core API

### Key Generation

```go
// Generate a new key pair for signing a specified number of messages
keyPair, err := core.GenerateKeyPair(messageCount, nil)

// Derive a public key from a private key
publicKey, err := core.DerivePublicKey(privateKey, messageCount)
```

### Signature Operations

```go
// Sign messages
signature, err := core.Sign(privateKey, publicKey, messages, nil)

// Verify a signature
err := core.Verify(publicKey, signature, messages, nil)
```

### Proof Operations

```go
// Create a selective disclosure proof
proof, disclosedMsgs, err := core.CreateProof(
    publicKey,
    signature,
    messages,
    disclosedIndices,
    nil,
)

// Verify a proof
err := core.VerifyProof(publicKey, proof, disclosedMsgs, nil)

// Batch verify multiple proofs
err := core.BatchVerifyProofs(keys, proofs, disclosedMsgsList, headers)
```

## Credential Management

The `pkg/credential` package provides high-level APIs for credential management:

```go
// Create a credential
builder := credential.NewBuilder()
builder.SetSchema("https://example.com/schemas/identity")
builder.SetIssuer("Example Issuer")
builder.AddAttribute("name", "John Doe")
builder.AddAttribute("age", "30")
builder.AddAttribute("email", "john@example.com")

// Issue the credential
cred, err := builder.Issue(keyPair)

// Create a presentation
presentation, err := cred.CreatePresentation([]string{"name"})

// Verify a presentation
verifier := credential.NewVerifier()
verifier.SetPublicKey(publicKey)
verifier.SetPresentation(presentation)
err := verifier.Verify()
```

## Proof Operations

The `pkg/proof` package provides advanced proof operations:

```go
// Create a proof with custom options
proofBuilder := proof.NewBuilder()
proofBuilder.SetSignature(signature)
proofBuilder.SetMessages(messages)
proofBuilder.Disclose(0, 2)
proofBuilder.AddPredicate(1, proof.PredicateGreaterThan, 18)
p, disclosed, err := proofBuilder.Build()

// Verify a proof with custom options
verifier := proof.NewVerifier()
verifier.SetPublicKey(publicKey)
verifier.SetProof(p)
verifier.SetDisclosedMessages(disclosed)
err := verifier.Verify()
```

## Cryptographic Primitives

The `pkg/crypto` package provides low-level cryptographic operations:

```go
// Multi-scalar multiplication
result, err := crypto.MultiScalarMulG1(points, scalars)

// Hash to G1
point, err := crypto.HashToG1(message, DST_G1)
```

For performance-critical applications, the `pkg/crypto/simd` package provides SIMD-accelerated operations:

```go
// SIMD-accelerated multi-scalar multiplication
result, err := simd.MultiScalarMulG1(points, scalars, simd.OptimizationAuto)
```

## Utilities

The `pkg/utils` package provides utility functions:

```go
// Constant-time operations
inverse := utils.ConstantTimeModInverse(value, modulus)

// Secure random scalar generation
scalar, err := utils.RandomScalar(rand.Reader)

// Message conversion
fieldElement := utils.MessageToFieldElement(messageBytes)
```

## WebAssembly Integration

The `pkg/wasm` package provides WebAssembly bindings for browser integration:

```javascript
// Generate a key pair
const keyPair = generateKeyPair(5);

// Sign messages
const signature = sign(
    keyPair.privateKey,
    keyPair.publicKey,
    { messages: ["message1", "message2", "message3", "message4", "message5"] }
);

// Create a proof
const proof = createProof({
    messages: ["message1", "message2", "message3", "message4", "message5"],
    disclosedIndices: [0, 2],
    signature: signature.signature,
    publicKey: keyPair.publicKey
});
```

## Examples

The `examples/` directory contains extensive examples of using the BBS+ library:

- `examples/main.go`: Basic usage example
- `examples/credential_scenarios/`: Real-world credential scenarios
- `examples/migration.go`: Migration from old to new package structure

## Security Considerations

The BBS+ implementation includes several security hardening measures:

- Constant-time operations for sensitive cryptographic functions
- Secure random number generation
- Memory management to avoid leaks
- Input validation to prevent attacks
- Side-channel resistance in critical operations

For a complete security analysis, see the [security_report.md](../security_report.md) document.