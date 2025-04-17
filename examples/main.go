// This is an example application demonstrating the BBS+ signature scheme.
// It creates a signature, verifies it, creates a selective disclosure proof,
// and verifies the proof.
package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/asv/bbs/bbs"
)

func run_bbs_demo() {
	// Number of messages we want to sign
	messageCount := 5
	
	// Generate a new key pair for signing 5 messages
	fmt.Println("Generating key pair...")
	keyPair, err := bbs.GenerateKeyPair(messageCount, nil)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	fmt.Println("Key pair generated successfully!")
	
	// Create some sample messages
	messageStrings := []string{
		"Message 1: Name = John Doe",
		"Message 2: Date of Birth = 1990-01-01",
		"Message 3: Address = 123 Main St",
		"Message 4: ID Number = ABC123456",
		"Message 5: Nationality = USA",
	}
	
	// Convert messages to field elements
	fmt.Println("\nConverting messages to field elements...")
	messages := make([]*big.Int, messageCount)
	for i, msg := range messageStrings {
		msgBytes := bbs.MessageToBytes(msg)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
		fmt.Printf("Message %d: %s -> %s...\n", i+1, msg, messages[i].String()[:20])
	}
	
	// Sign the messages
	fmt.Println("\nSigning messages...")
	signature, err := bbs.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
	if err != nil {
		log.Fatalf("Failed to sign messages: %v", err)
	}
	fmt.Println("Signature created successfully!")
	
	// Verify the signature
	fmt.Println("\nVerifying signature...")
	
	// Display signature components
	fmt.Println("Signature components:")
	fmt.Printf("A: %s\n", signature.A.String()[:50]+"...")
	fmt.Printf("E: %s\n", signature.E.String())
	fmt.Printf("S: %s\n", signature.S.String())
	
	err = bbs.Verify(keyPair.PublicKey, signature, messages, nil)
	if err != nil {
		log.Fatalf("Verification failed with error: %v", err)
	}
	fmt.Println("✅ Signature verified successfully!")
	
	// Create a selective disclosure proof
	// Let's disclose only messages 0 and 2 (Name and Address)
	disclosedIndices := []int{0, 2}
	fmt.Printf("\nCreating selective disclosure proof (disclosing messages: Name, Address)...\n")
	
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
	fmt.Println("Proof created successfully!")
	
	// Verify the proof
	fmt.Println("\nVerifying selective disclosure proof...")
	
	// Display proof components
	fmt.Println("Proof components:")
	fmt.Printf("APrime: %s\n", proof.APrime.String()[:50]+"...")
	fmt.Printf("ABar: %s\n", proof.ABar.String()[:50]+"...")
	fmt.Printf("D: %s\n", proof.D.String()[:50]+"...")
	
	err = bbs.VerifyProof(keyPair.PublicKey, proof, disclosedMsgs, nil)
	if err != nil {
		log.Fatalf("Proof verification failed with error: %v", err)
	}
	fmt.Println("✅ Proof verified successfully!")
	
	// Print which messages were disclosed
	fmt.Println("\nDisclosed messages:")
	for i, idx := range disclosedIndices {
		originalMsg := messageStrings[idx]
		disclosedIdx := i // Map from disclosedIndices index to disclosedMsgs index
		msgVal := disclosedMsgs[disclosedIdx]
		fmt.Printf("Message %d: %s -> %s...\n", idx+1, originalMsg, msgVal.String()[:20])
	}
	
	// Test negative case: try to verify with tampered message
	fmt.Println("\n🧪 Testing tampered message rejection:")
	// Make a copy of the disclosed messages with one being tampered
	tamperedMsgs := make(map[int]*big.Int)
	i := 0
	for range disclosedIndices {
		if i == 0 {
			// Tamper the first disclosed message
			tamperedMsgs[i] = big.NewInt(12345)
		} else {
			tamperedMsgs[i] = disclosedMsgs[i]
		}
		i++
	}
	
	// Verify should fail with tampered message
	err = bbs.VerifyProof(keyPair.PublicKey, proof, tamperedMsgs, nil)
	if err != nil {
		fmt.Printf("✅ Correctly rejected tampered proof: %v\n", err)
	} else {
		fmt.Println("❌ Error: Tampered proof was incorrectly verified!")
	}
	
	fmt.Println("\nFor more credential examples, run the programs in examples/credential_scenarios/")
	fmt.Println("  - healthcare_credential.go  - Healthcare credential scenarios")
	fmt.Println("  - digital_identity.go       - Digital identity credential scenarios")
	fmt.Println("  - academic_credentials.go   - Academic credential scenarios")
	
	fmt.Println("\nBBS+ demonstration completed successfully!")
}

func RunExample() {
	run_bbs_demo()
}

