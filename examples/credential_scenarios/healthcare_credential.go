// Healthcare credential example demonstrating BBS+ for medical records privacy
package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/anupsv/bbsplus-signatures/bbs"
)

func RunHealthcareCredentialExample() {
	fmt.Println("Healthcare Credential Example - Using BBS+ signatures")
	fmt.Println("====================================================")

	// Define healthcare credential attributes
	// In a real system, these could be standardized across healthcare providers
	messageCount := 7
	messageStrings := []string{
		"Patient Name: John Smith",
		"Patient DOB: 1980-05-15",
		"Patient ID: 123456789",
		"Insurance ID: INS-987654",
		"Blood Type: O+",
		"Allergies: Penicillin",
		"Primary Doctor: Dr. Jane Wilson",
	}

	fmt.Println("\nGenerating healthcare credential with the following attributes:")
	for _, msg := range messageStrings {
		fmt.Printf("  - %s\n", msg)
	}

	// Generate a key pair for the healthcare authority
	fmt.Println("\nGenerating authority key pair...")
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

	// Sign the credential with all attributes
	fmt.Println("Healthcare authority signing credential...")
	signature, err := bbs.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
	if err != nil {
		log.Fatalf("Failed to sign credential: %v", err)
	}
	fmt.Println("Credential signed successfully!")

	// Verify the full credential (all attributes)
	fmt.Println("\nVerifying complete credential...")
	err = bbs.Verify(keyPair.PublicKey, signature, messages, nil)
	if err != nil {
		log.Fatalf("Credential verification failed: %v", err)
	}
	fmt.Println("Full credential verified successfully!")

	// Create selective disclosure proofs for different scenarios
	// Scenario 1: Emergency room - only needs blood type, allergies
	fmt.Println("\n🚨 SCENARIO 1: Emergency Room 🚨")
	fmt.Println("Requirements: Only need to know patient's blood type and allergies")
	emergencyIndices := []int{4, 5} // Blood type, allergies

	emergencyProof, emergencyDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		emergencyIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create emergency proof: %v", err)
	}

	// Verify emergency proof
	err = bbs.VerifyProof(keyPair.PublicKey, emergencyProof, emergencyDisclosed, nil)
	if err != nil {
		log.Fatalf("Emergency proof verification failed: %v", err)
	}

	// Display disclosed attributes for emergency
	fmt.Println("Disclosed attributes for emergency room:")
	for _, idx := range emergencyIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("Emergency disclosure proof verified successfully!")

	// Scenario 2: Insurance company - needs patient ID, insurance ID, treatment codes
	fmt.Println("\n💰 SCENARIO 2: Insurance Company 💰")
	fmt.Println("Requirements: Need patient ID and insurance ID")
	insuranceIndices := []int{2, 3} // Patient ID, Insurance ID

	insuranceProof, insuranceDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		insuranceIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create insurance proof: %v", err)
	}

	// Verify insurance proof
	err = bbs.VerifyProof(keyPair.PublicKey, insuranceProof, insuranceDisclosed, nil)
	if err != nil {
		log.Fatalf("Insurance proof verification failed: %v", err)
	}

	// Display disclosed attributes for insurance
	fmt.Println("Disclosed attributes for insurance company:")
	for _, idx := range insuranceIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("Insurance disclosure proof verified successfully!")

	// Scenario 3: Referral to specialist - needs most info except insurance details
	fmt.Println("\n👩‍⚕️ SCENARIO 3: Specialist Referral 👨‍⚕️")
	fmt.Println("Requirements: Need patient info and medical details, but not insurance info")
	referralIndices := []int{0, 1, 2, 4, 5, 6} // All except insurance ID

	referralProof, referralDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		referralIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create referral proof: %v", err)
	}

	// Verify referral proof
	err = bbs.VerifyProof(keyPair.PublicKey, referralProof, referralDisclosed, nil)
	if err != nil {
		log.Fatalf("Referral proof verification failed: %v", err)
	}

	// Display disclosed attributes for referral
	fmt.Println("Disclosed attributes for specialist referral:")
	for _, idx := range referralIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("Specialist referral disclosure proof verified successfully!")

	fmt.Println("\nHealthcare credential example completed successfully!")
}
