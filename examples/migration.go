// Example showing migration from the old package structure to the new one
package main

import (
	"fmt"
	"math/big"

	// Old imports
	"github.com/asv/bbs/bbs"
	
	// New imports for intermediate migration
	compat "github.com/asv/bbs/pkg/bbscompat"
	
	// New imports for complete migration
	"github.com/asv/bbs/pkg/core"
)

func RunMigrationExample() {
	fmt.Println("BBS+ Package Migration Example")
	fmt.Println("==============================")
	
	// Original usage with the bbs package
	fmt.Println("\n1. Original usage with bbs package:")
	originalExample()
	
	// Intermediate migration with compatibility layer
	fmt.Println("\n2. Using compatibility layer:")
	compatExample()
	
	// Complete migration with new packages
	fmt.Println("\n3. Using new package structure:")
	newPackageExample()
	
	// Using new credential features
	fmt.Println("\n4. Using new credential features:")
	credentialExample()
}

// Original usage with the bbs package
func originalExample() {
	// Generate a key pair
	keyPair, _ := bbs.GenerateKeyPair(3, nil)
	fmt.Println("  Generated key pair with old package")
	
	// Create messages
	messages := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
	}
	
	// Sign messages
	signature, _ := bbs.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
	fmt.Println("  Signed messages with old package")
	
	// Verify signature
	err := bbs.Verify(keyPair.PublicKey, signature, messages, nil)
	if err == nil {
		fmt.Println("  Verified signature with old package")
	}
	
	// Create proof
	disclosedIndices := []int{0, 2}
	proof, disclosed, _ := bbs.CreateProof(keyPair.PublicKey, signature, messages, disclosedIndices, nil)
	fmt.Println("  Created proof with old package")
	
	// Verify proof
	err = bbs.VerifyProof(keyPair.PublicKey, proof, disclosed, nil)
	if err == nil {
		fmt.Println("  Verified proof with old package")
	}
}

// Intermediate migration with compatibility layer
func compatExample() {
	// Generate a key pair using the compatibility layer
	keyPair, _ := compat.GenerateKeyPair(3, nil)
	fmt.Println("  Generated key pair with compatibility layer")
	
	// Create messages
	messages := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
	}
	
	// Sign messages using the compatibility layer
	signature, _ := compat.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
	fmt.Println("  Signed messages with compatibility layer")
	
	// Verify signature using the compatibility layer
	err := compat.Verify(keyPair.PublicKey, signature, messages, nil)
	if err == nil {
		fmt.Println("  Verified signature with compatibility layer")
	}
	
	// Create proof using the compatibility layer
	disclosedIndices := []int{0, 2}
	proof, disclosed, _ := compat.CreateProof(keyPair.PublicKey, signature, messages, disclosedIndices, nil)
	fmt.Println("  Created proof with compatibility layer")
	
	// Verify proof using the compatibility layer
	err = compat.VerifyProof(keyPair.PublicKey, proof, disclosed, nil)
	if err == nil {
		fmt.Println("  Verified proof with compatibility layer")
	}
}

// Complete migration with new packages
func newPackageExample() {
	// Generate a key pair using the new core package
	keyPair, _ := core.GenerateKeyPair(3, nil)
	fmt.Println("  Generated key pair with new package")
	
	// Create messages
	messages := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
	}
	
	// Sign messages using the new core package
	signature, _ := core.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
	fmt.Println("  Signed messages with new package")
	
	// Verify signature using the new core package
	err := core.Verify(keyPair.PublicKey, signature, messages, nil)
	if err == nil {
		fmt.Println("  Verified signature with new package")
	}
	
	// Create proof using the new core package
	disclosedIndices := []int{0, 2}
	proof, disclosed, _ := core.CreateProof(keyPair.PublicKey, signature, messages, disclosedIndices, nil)
	fmt.Println("  Created proof with new package")
	
	// Verify proof using the new core package
	err = core.VerifyProof(keyPair.PublicKey, proof, disclosed, nil)
	if err == nil {
		fmt.Println("  Verified proof with new package")
	}
}

// Using the new credential features
func credentialExample() {
	// Skip actual execution since this is just for example purposes
	fmt.Println("  This shows the new credential API (code only):")
	fmt.Println("  -------------------------------------------")
	fmt.Println("  // Create a credential builder")
	fmt.Println("  builder := credential.NewBuilder()")
	fmt.Println("  builder.SetSchema(\"https://example.com/schemas/identity\")")
	fmt.Println("  builder.SetIssuer(\"Example Issuer\")")
	fmt.Println("  builder.AddAttribute(\"name\", \"John Doe\")")
	fmt.Println("  builder.AddAttribute(\"age\", \"30\")")
	fmt.Println("  builder.AddAttribute(\"email\", \"john@example.com\")")
	fmt.Println()
	fmt.Println("  // Issue the credential")
	fmt.Println("  cred, _ := builder.Issue(keyPair)")
	fmt.Println()
	fmt.Println("  // Create a presentation")
	fmt.Println("  presentation, _ := cred.CreatePresentation([]string{\"name\"})")
	fmt.Println()
	fmt.Println("  // Verify the presentation")
	fmt.Println("  verifier := credential.NewVerifier()")
	fmt.Println("  verifier.SetPublicKey(keyPair.PublicKey)")
	fmt.Println("  verifier.SetPresentation(presentation)")
	fmt.Println("  err := verifier.Verify()")
}