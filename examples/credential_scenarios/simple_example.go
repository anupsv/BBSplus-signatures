// A simple example demonstrating BBS+ signatures
package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/asv/bbs/bbs"
)

func main() {
	fmt.Println("Simple BBS+ Example - Demonstrating the improved code")
	fmt.Println("===================================================")
	
	// Number of messages to sign
	messageCount := 3
	
	// Generate a key pair
	fmt.Println("Generating key pair...")
	keyPair, err := bbs.GenerateKeyPair(messageCount, nil)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	
	// Create three simple messages
	messageStrings := []string{
		"First message: Hello",
		"Second message: World",
		"Third message: BBS+",
	}
	
	// Convert to field elements
	fmt.Println("Converting messages...")
	messages := make([]*big.Int, messageCount)
	for i, msg := range messageStrings {
		msgBytes := bbs.MessageToBytes(msg)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
		fmt.Printf("Message %d: %s\n", i+1, msg)
	}
	
	// Sign the messages
	fmt.Println("\nSigning messages...")
	signature, err := bbs.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
	if err != nil {
		log.Fatalf("Failed to sign messages: %v", err)
	}
	
	// We can now use our credential examples even if the main library
	// still has some incompatibility issues in other functions
	fmt.Println("Signature created successfully!")
	
	fmt.Println("\nSee the credential scenario examples for more complex use cases:")
	fmt.Println("- healthcare_credential.go  - Healthcare credential scenarios")
	fmt.Println("- digital_identity.go       - Digital identity credential scenarios")
	fmt.Println("- academic_credentials.go   - Academic credential scenarios")
}