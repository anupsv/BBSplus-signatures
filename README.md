# BBS+ Signatures

A Go implementation of BBS+ signatures on the BLS12-381 curve with selective disclosure proofs.

> **WARNING**: This code is NOT audited and should be used for EDUCATIONAL PURPOSES ONLY. 
> It is not suitable for production use or applications requiring actual security.

## Overview

BBS+ is a pairing-based cryptographic signature scheme that allows for selective disclosure of signed messages. It's particularly useful for privacy-preserving applications such as verifiable credentials and zero-knowledge proofs.

The implementation uses the BLS12-381 elliptic curve pairing from the [gnark-crypto](https://github.com/consensys/gnark-crypto) library, which provides efficient cryptographic operations over pairing-friendly curves.

## Features

- **BLS12-381 Support:** Uses the BLS12-381 pairing-friendly elliptic curve
- **Selective Disclosure:** Create zero-knowledge proofs revealing only specific attributes
- **Optimized Implementation:** Uses efficient cryptographic operations and batch processing
- **Credential Scenarios:** Example implementations for various real-world use cases

## Current Status

This implementation includes all necessary security and functionality improvements:

- [x] Secure key management with proper hashing of generator points with domain separation
- [x] Added domain separation tags for hashing to curve points
- [x] Optimized MultiScalarMulG1 implementation for improved performance and security
- [x] Fixed verification issues in the core cryptographic operations
- [x] Added real-world credential scenario examples

## Getting Started

### Prerequisites

- Go 1.19 or later

### Installation

```bash
git clone https://github.com/anupsv/bbsplus-signatures.git
cd bbs
go mod tidy
```

### Project Structure

The project is organized as follows:

- `bbs/` - Main library package with the core implementation
- `bbs/perf/` - Performance benchmarking tools
- `examples/` - Example applications showing usage of the library
  - `examples/credential_scenarios/` - Real-world use case examples
- `tools/` - Additional utilities and test programs
- `bin/` - Compiled binaries
- `vendor/` - Vendored dependencies

### Running the Demo

```bash
# Run the main example
go run main.go

# Run credential scenario examples
go run examples/credential_scenarios/healthcare_credential.go
go run examples/credential_scenarios/digital_identity.go
go run examples/credential_scenarios/academic_credentials.go

# Run all examples
cd examples/credential_scenarios
./run_all.sh
```

## Basic Usage

```go
package main

import (
    "fmt"
    "log"
    "math/big"
    
    "github.com/anupsv/bbsplus-signatures/bbs"
)

func main() {
    // Number of messages we want to sign
    messageCount := 5
    
    // Generate a new key pair for signing 5 messages
    keyPair, err := bbs.GenerateKeyPair(messageCount, nil)
    if err != nil {
        log.Fatalf("Failed to generate key pair: %v", err)
    }
    
    // Create some sample messages
    messageStrings := []string{
        "Message 1: Name = John Doe",
        "Message 2: Date of Birth = 1990-01-01",
        "Message 3: Address = 123 Main St",
        "Message 4: ID Number = ABC123456",
        "Message 5: Nationality = USA",
    }
    
    // Convert messages to field elements
    messages := make([]*big.Int, messageCount)
    for i, msg := range messageStrings {
        msgBytes := bbs.MessageToBytes(msg)
        messages[i] = bbs.MessageToFieldElement(msgBytes)
    }
    
    // Sign the messages
    signature, err := bbs.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
    if err != nil {
        log.Fatalf("Failed to sign messages: %v", err)
    }
    
    // Verify the signature
    err = bbs.Verify(keyPair.PublicKey, signature, messages, nil)
    if err != nil {
        log.Fatalf("Failed to verify signature: %v", err)
    }
    
    // Create a selective disclosure proof revealing only messages 0 and 2
    disclosedIndices := []int{0, 2}
    proof, disclosedMsgs, err := bbs.CreateProof(
        keyPair.PublicKey,
        signature,
        messages,
        disclosedIndices,
        nil,
    )
    if err != nil {
        log.Fatalf("Failed to create proof: %v", err)
    }
    
    // Verify the proof
    err = bbs.VerifyProof(keyPair.PublicKey, proof, disclosedMsgs, nil)
    if err != nil {
        log.Fatalf("Failed to verify proof: %v", err)
    }
}
```

## Real-world Credential Scenarios

The library includes examples of how BBS+ signatures can be used in practical applications:

### Healthcare Credentials
Demonstrates how healthcare information can be selectively disclosed:
- Emergency scenarios (only blood type and allergies)
- Insurance verification (only policy and ID information)
- Medical referrals (share relevant medical details while withholding sensitive information)

### Digital Identity
Shows how a digital identity can be used in different contexts:
- Age verification (minimal disclosure)
- Online account registration
- Travel identification
- KYC for financial services

### Academic Credentials
Demonstrates selective disclosure of academic achievements:
- Job application (basic degree verification)
- Graduate school application (detailed academic record)
- Transcript verification
- Scholarship application

## Performance

### MultiScalarMulG1 Optimization

The library includes an optimized implementation of the MultiScalarMulG1 function:

1. **Fixed Critical Bug:** Corrected the initialization of identity points
2. **Batch Processing:** Improved cache locality by processing points in batches
3. **Safer Error Handling:** Better detection and reporting of error conditions

### Running Benchmarks

```bash
go test -bench=. ./bbs
```

## Technical Details

### Cryptographic Improvements

- **Identity Point Initialization:** Fixed Z=0 bug by ensuring Z=1 for identity points
- **Domain Separation:** Added proper domain separation tags for hashing to curve
- **Error Handling:** Improved error reporting and detection
- **Constant-Time Operations:** Used constant-time operations for sensitive functionality
- **Type Safety:** Fixed various type conversions between Jacobian and Affine coordinates

## Contributing

Contributions are welcome! Here are some areas that need attention:

1. Complete refactoring of proof-related code to fix type compatibility issues
2. Add comprehensive test coverage for all functionality
3. Implement more advanced features like predicates and range proofs
4. Enhance documentation with more examples
5. Add support for serialization formats (JSON, CBOR)

## References

- [gnark-crypto](https://github.com/consensys/gnark-crypto) - For elliptic curve operations and pairing-based cryptography
- [BBS+ Algorithm Documentation](https://github.com/mattrglobal/bbs-signatures/blob/master/docs/ALGORITHM.md)
- [IRTF cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
- [Pairing-based Cryptography](https://en.wikipedia.org/wiki/Pairing-based_cryptography)

## Changelog

For a detailed list of changes, see [CHANGELOG.md](CHANGELOG.md)