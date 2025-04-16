// Digital identity credential example demonstrating BBS+ for identity verification
package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/asv/bbs/bbs"
)

func main() {
	fmt.Println("Digital Identity Credential Example - Using BBS+ signatures")
	fmt.Println("========================================================")
	
	// Define digital identity credential attributes
	messageCount := 9
	messageStrings := []string{
		"Full Name: Alice Johnson",
		"Date of Birth: 1992-03-25",
		"Nationality: Canadian",
		"ID Number: ID-12345678",
		"Address: 123 Maple St, Toronto, ON",
		"Phone Number: +1-555-123-4567",
		"Email: alice@example.com",
		"Biometric Hash: 26ae5cc854e9f9c29b49e866042a604c",
		"Credential Issuance Date: 2023-11-15",
	}
	
	fmt.Println("\nGenerating digital identity with the following attributes:")
	for _, msg := range messageStrings {
		fmt.Printf("  - %s\n", msg)
	}
	
	// Generate a key pair for the identity issuer (government, bank, etc.)
	fmt.Println("\nGenerating issuer key pair...")
	keyPair, err := bbs.GenerateKeyPair(messageCount, nil)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	
	// Convert messages to field elements
	messages := make([]*big.Int, messageCount)
	for i, msg := range messageStrings {
		msgBytes := bbs.MessageToBytes(msg)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
	}
	
	// Sign the identity credential with all attributes
	fmt.Println("Identity authority signing credential...")
	signature, err := bbs.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
	if err != nil {
		log.Fatalf("Failed to sign credential: %v", err)
	}
	fmt.Println("Identity credential signed successfully!")
	
	// Scenario 1: Age verification (minimal disclosure) - only reveal person is over 18
	// In a real implementation, we'd use a zero-knowledge predicate proof, but for this example
	// we'll just disclose the DOB
	fmt.Println("\n🍸 SCENARIO 1: Age Verification 🍸")
	fmt.Println("Requirements: Only need to verify person is over 18")
	ageIndices := []int{1} // Date of birth
	
	ageProof, ageDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		ageIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create age verification proof: %v", err)
	}
	
	// Verify age proof
	err = bbs.VerifyProof(keyPair.PublicKey, ageProof, ageDisclosed, nil)
	if err != nil {
		log.Fatalf("Age verification proof failed: %v", err)
	}
	
	// Display disclosed attributes for age verification
	fmt.Println("Disclosed attributes for age verification:")
	for _, idx := range ageIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("Age verification proof verified successfully!")
	
	// Scenario 2: Online account registration - name, email, phone
	fmt.Println("\n💻 SCENARIO 2: Online Account Registration 💻")
	fmt.Println("Requirements: Need name, email and phone for account creation")
	registrationIndices := []int{0, 5, 6} // Name, phone, email
	
	registrationProof, registrationDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		registrationIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create registration proof: %v", err)
	}
	
	// Verify registration proof
	err = bbs.VerifyProof(keyPair.PublicKey, registrationProof, registrationDisclosed, nil)
	if err != nil {
		log.Fatalf("Registration proof verification failed: %v", err)
	}
	
	// Display disclosed attributes for registration
	fmt.Println("Disclosed attributes for online registration:")
	for _, idx := range registrationIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("Registration disclosure proof verified successfully!")
	
	// Scenario 3: Travel identification - full identity details except contact info
	fmt.Println("\n✈️ SCENARIO 3: Border Control / Travel Identification ✈️")
	fmt.Println("Requirements: Need full identification but not contact information")
	travelIndices := []int{0, 1, 2, 3, 4, 7, 8} // All except phone, email
	
	travelProof, travelDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		travelIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create travel ID proof: %v", err)
	}
	
	// Verify travel proof
	err = bbs.VerifyProof(keyPair.PublicKey, travelProof, travelDisclosed, nil)
	if err != nil {
		log.Fatalf("Travel ID proof verification failed: %v", err)
	}
	
	// Display disclosed attributes for travel identification
	fmt.Println("Disclosed attributes for travel identification:")
	for _, idx := range travelIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("Travel identification proof verified successfully!")
	
	// Scenario 4: Know Your Customer (KYC) verification - full identity
	fmt.Println("\n🏦 SCENARIO 4: KYC for Financial Services 🏦")
	fmt.Println("Requirements: Full identity disclosure required")
	kycIndices := []int{0, 1, 2, 3, 4, 5, 6, 7, 8} // All attributes
	
	kycProof, kycDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		kycIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create KYC proof: %v", err)
	}
	
	// Verify KYC proof
	err = bbs.VerifyProof(keyPair.PublicKey, kycProof, kycDisclosed, nil)
	if err != nil {
		log.Fatalf("KYC proof verification failed: %v", err)
	}
	
	// Display disclosed attributes for KYC
	fmt.Println("Disclosed attributes for KYC verification:")
	for _, idx := range kycIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("KYC verification proof verified successfully!")
	
	fmt.Println("\nDigital identity credential example completed successfully!")
}