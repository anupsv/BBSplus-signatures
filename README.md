# BBS+ Signatures

A Go implementation of BBS+ signatures on BLS12-381 curve with selective disclosure proofs.

> **WARNING**: This code is NOT audited and should be used for EDUCATIONAL PURPOSES ONLY. 
> It is not suitable for production use or applications requiring actual security.

## Current Status

This implementation includes all necessary security and functionality improvements. The following key features have been implemented:

- [x] Secure key management with proper hashing of generator points with domain separation
- [x] Added domain separation tags for hashing to curve points
- [x] Updated MultiScalarMulG1 function calls to handle errors properly
- [x] Improved preprocessing with proper error handling

The following items still need to be addressed:

- [ ] Fix G2 point conversion in `keygen.go` (the `g2ToAffine` function contains placeholder code)
- [ ] Complete test coverage for all functionality

## Features

- **BLS12-381 Support:** Uses the BLS12-381 pairing-friendly elliptic curve
- **Selective Disclosure:** Create zero-knowledge proofs revealing only specific attributes
- **Performance Optimized:** Uses efficient cryptographic operations

## Overview

BBS+ is a pairing-based cryptographic signature scheme that allows for selective disclosure of signed messages. It's particularly useful for privacy-preserving applications such as verifiable credentials and zero-knowledge proofs.

The implementation uses the `BLS12-381` elliptic curve pairing from the [gnark-crypto](https://github.com/consensys/gnark-crypto) library, which provides efficient cryptographic operations over pairing-friendly curves.

## Getting Started

### Prerequisites

- Go 1.19 or later

### Installation

```bash
git clone https://github.com/asv/bbs.git
cd bbs
go mod tidy
```

### Setup

No additional setup is needed beyond installation. The codebase is ready to use.

### Running the Demo

```bash
go run main.go
```

## Basic Usage

```go
package main

import (
    "fmt"
    "log"
    "math/big"
    
    "github.com/asv/bbs/bbs"
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

## Performance

### Running Benchmarks

```bash
go test -bench=. ./bbs
```

## Contributing

Contributions are welcome! Here are some areas that need attention:

1. Complete the implementation of `g2ToAffine` in `keygen.go` with proper Z-coordinate normalization
2. Add more comprehensive tests
3. Improve documentation
4. Enhance performance benchmarking and profiling

## References

- [gnark-crypto](https://github.com/consensys/gnark-crypto) - For elliptic curve operations and pairing-based cryptography
- [BBS+ Algorithm Documentation](https://github.com/mattrglobal/bbs-signatures/blob/master/docs/ALGORITHM.md)
- [Pairing-based Cryptography](https://en.wikipedia.org/wiki/Pairing-based_cryptography)