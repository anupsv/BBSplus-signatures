# BBS+ Library Migration Guide

This guide helps you migrate from the original flat package structure to the new organized package structure.

## Why Reorganize?

The reorganized package structure provides several benefits:

1. **Better Separation of Concerns**: Each package has a well-defined responsibility
2. **Improved Maintainability**: Smaller, focused packages are easier to maintain
3. **Cleaner API**: Public APIs are clearly separated from implementation details
4. **Enhanced Documentation**: Better package-level documentation
5. **Improved Testing**: Focused tests for each package

## Migration Steps

### 1. Update Import Paths

Replace imports from the original package with the new packages:

**Original:**
```go
import "github.com/asv/bbs/bbs"
```

**New:**
```go
import "github.com/asv/bbs/pkg/core"
```

### 2. Use the Compatibility Package (Optional)

If you want to minimize changes during migration, you can use the compatibility package:

```go
import "github.com/asv/bbs/pkg/bbscompat"
```

This package re-exports all the types and functions from the original package with the same names, making it easier to migrate gradually.

### 3. Use the New Package Structure

For new code or complete migration, use the specialized packages:

```go
import (
    "github.com/asv/bbs/pkg/core"       // Core BBS+ functionality
    "github.com/asv/bbs/pkg/credential" // Credential management
    "github.com/asv/bbs/pkg/proof"      // Proof operations
)
```

## Package Map

Here's a guide to which packages contain the functionality from the original package:

| Original Functionality        | New Package                        |
|------------------------------|-----------------------------------|
| `GenerateKeyPair`            | `pkg/core`                         |
| `Sign`                       | `pkg/core`                         |
| `Verify`                     | `pkg/core`                         |
| `CreateProof`                | `pkg/core` or `pkg/proof`          |
| `VerifyProof`                | `pkg/core` or `pkg/proof`          |
| `BatchVerifyProofs`          | `pkg/core` or `pkg/proof`          |
| `KeyPair`, `Signature` types | `pkg/core`                         |
| `ProofOfKnowledge` type      | `pkg/core` or `pkg/proof`          |
| Object pooling               | `internal/pool` (not public API)    |
| Crypto operations            | `pkg/crypto`                       |
| Constant-time functions      | `pkg/utils`                        |
| Credential operations        | `pkg/credential` (new)             |

## Example Migration

### Original Code:

```go
package main

import (
    "github.com/asv/bbs/bbs"
)

func main() {
    keyPair, _ := bbs.GenerateKeyPair(5, nil)
    signature, _ := bbs.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
    err := bbs.Verify(keyPair.PublicKey, signature, messages, nil)
}
```

### Migrated Code:

```go
package main

import (
    "github.com/asv/bbs/pkg/core"
)

func main() {
    keyPair, _ := core.GenerateKeyPair(5, nil)
    signature, _ := core.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
    err := core.Verify(keyPair.PublicKey, signature, messages, nil)
}
```

## New Features

The reorganized package structure introduces new functionality:

1. **Credential Management**: The `pkg/credential` package provides high-level credential operations
2. **Presentation Creation**: Create and verify selective disclosure presentations
3. **Enhanced Proofs**: The `pkg/proof` package offers more advanced proof operations
4. **Fluent Interfaces**: Builder and verifier patterns for easier usage

## Need Help?

If you encounter any issues during migration, please open an issue on GitHub.