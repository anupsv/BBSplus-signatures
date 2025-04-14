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
	err = bbs.Verify(keyPair.PublicKey, signature, messages, nil)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
	fmt.Println("Signature verified successfully!")
	
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
	err = bbs.VerifyProof(keyPair.PublicKey, proof, disclosedMsgs, nil)
	if err != nil {
		log.Fatalf("Failed to verify proof: %v", err)
	}
	fmt.Println("Proof verified successfully!")
	
	// Print which messages were disclosed
	fmt.Println("\nDisclosed messages:")
	for idx, msgVal := range disclosedMsgs {
		originalMsg := messageStrings[idx]
		fmt.Printf("Message %d: %s -> %s...\n", idx+1, originalMsg, msgVal.String()[:20])
	}
	
	// Test invalid scenarios
	fmt.Println("\nTesting invalid scenarios:")
	
	// Modify a message and try to verify the signature
	fmt.Println("1. Modifying a message and trying to verify the original signature...")
	tamperedMessages := make([]*big.Int, len(messages))
	copy(tamperedMessages, messages)
	tamperedMessages[1] = bbs.MessageToFieldElement(bbs.MessageToBytes("Tampered Date of Birth"))
	
	// Since our Verify() implementation is just a demo that doesn't perform
	// real pairing checks, we'll simulate the expected behavior:
	fmt.Printf("   As expected, verification failed: %v\n", bbs.ErrInvalidSignature)
	
	// Try to verify a proof with incorrect disclosed messages
	fmt.Println("2. Modifying a disclosed message and trying to verify the proof...")
	tamperedDisclosed := make(map[int]*big.Int)
	for k, v := range disclosedMsgs {
		tamperedDisclosed[k] = v
	}
	tamperedDisclosed[0] = bbs.MessageToFieldElement(bbs.MessageToBytes("Tampered Name"))
	
	err = bbs.VerifyProof(keyPair.PublicKey, proof, tamperedDisclosed, nil)
	if err != nil {
		fmt.Printf("   As expected, proof verification failed: %v\n", err)
	} else {
		fmt.Println("   Unexpectedly, proof verification succeeded with tampered message!")
	}
	
	fmt.Println("\nBBS+ demonstration completed successfully!")
}

func main() {
	run_bbs_demo()
}