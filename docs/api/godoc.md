# Generating and Hosting GoDoc

This document explains how to generate and host API documentation for the BBS+ library using GoDoc.

## Generating Documentation Locally

To generate and view documentation locally, you can use the `godoc` command-line tool or the newer `pkgsite` tool.

### Using godoc

1. Install godoc:

```bash
go install golang.org/x/tools/cmd/godoc@latest
```

2. Run the godoc server from your project root:

```bash
godoc -http=:6060
```

3. Open your browser and navigate to `http://localhost:6060/pkg/github.com/asv/bbs/`

### Using pkgsite

1. Install pkgsite:

```bash
go install golang.org/x/pkgsite/cmd/pkgsite@latest
```

2. Run the pkgsite server from your project root:

```bash
pkgsite -http=:6060
```

3. Open your browser and navigate to `http://localhost:6060/github.com/asv/bbs/`

## Hosting Documentation on pkg.go.dev

The [pkg.go.dev](https://pkg.go.dev/) service automatically hosts documentation for your Go packages. To make your documentation available:

1. Make sure your repository is publicly accessible on GitHub or another source code hosting service.

2. Tag a release version using semantic versioning:

```bash
git tag v1.0.0
git push origin v1.0.0
```

3. Request documentation for your package by visiting `https://pkg.go.dev/github.com/asv/bbs`

## Best Practices for Writing GoDoc Comments

Follow these best practices to ensure high-quality documentation:

### Package Documentation

Add a package comment at the top of each package's main file (e.g., `doc.go`):

```go
// Package core provides the main functionality of the BBS+ signature scheme.
//
// It includes key generation, signing, verification, and proof creation/verification
// operations. This package is the main entry point for applications using the BBS+ library.
package core
```

### Function Documentation

Document each exported function with a clear description and examples:

```go
// Sign creates a BBS+ signature on the given messages using the provided key pair.
// The optional header provides domain separation.
//
// Example:
//
//     signature, err := core.Sign(privateKey, publicKey, messages, nil)
//     if err != nil {
//         // Handle error
//     }
func Sign(privateKey *PrivateKey, publicKey *PublicKey, messages []*big.Int, header []byte) (*Signature, error) {
    // Implementation
}
```

### Type Documentation

Document each exported type and its fields:

```go
// KeyPair represents a BBS+ key pair.
type KeyPair struct {
    // PrivateKey is the private key component.
    PrivateKey *PrivateKey
    
    // PublicKey is the public key component.
    PublicKey *PublicKey
    
    // MessageCount is the number of messages this key pair supports.
    MessageCount int
}
```

### Special Comments

Use special comment formats for better organization:

```go
// Deprecated: Use NewSignature instead.
func CreateSignature() {}

// Note: This function is not thread-safe.
func ProcessData() {}

// TODO: Add support for multiple signatures.
func VerifySignature() {}
```

## Setting Up GitHub Pages for Documentation

To host comprehensive documentation on GitHub Pages:

1. Create a `docs` directory in your repository.

2. Add an `index.html` file that provides an overview and links to the API documentation.

3. Enable GitHub Pages for your repository:
   - Go to your repository settings
   - Scroll down to the "GitHub Pages" section
   - Select the "main" branch and "/docs" folder
   - Click "Save"

4. Your documentation will be available at `https://username.github.io/bbs/`

## Generating Comprehensive Documentation

For more comprehensive documentation that includes diagrams, examples, and detailed explanations, consider using a documentation generator like [Hugo](https://gohugo.io/) with the [Docsy](https://www.docsy.dev/) theme:

1. Install Hugo:

```bash
# On macOS
brew install hugo

# On Linux
snap install hugo --channel=extended
```

2. Create a new Hugo site in the `docs` directory:

```bash
hugo new site docs
```

3. Add the Docsy theme:

```bash
cd docs
git init
git submodule add https://github.com/google/docsy.git themes/docsy
```

4. Configure Hugo to use the Docsy theme in `config.toml`:

```toml
theme = "docsy"
```

5. Create content in the `content` directory:

```bash
hugo new content/en/docs/getting-started.md
```

6. Build the documentation:

```bash
hugo
```

7. Deploy to GitHub Pages by committing the built site.