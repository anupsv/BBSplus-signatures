// Academic credentials example demonstrating BBS+ for educational verification
package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/asv/bbs/bbs"
)

func main() {
	fmt.Println("Academic Credential Example - Using BBS+ signatures")
	fmt.Println("=================================================")
	
	// Define academic credential attributes
	messageCount := 10
	messageStrings := []string{
		"Student Name: Emily Chen",
		"Student ID: STU-987654",
		"University: Tech University",
		"Degree: Bachelor of Science",
		"Major: Computer Science",
		"Minor: Mathematics",
		"GPA: 3.95/4.0",
		"Graduation Date: 2023-05-15",
		"Honors: Summa Cum Laude",
		"Transcript Hash: 3a7bd3e19e660f0ab8652c95909f99df",
	}
	
	fmt.Println("\nGenerating academic credential with the following attributes:")
	for _, msg := range messageStrings {
		fmt.Printf("  - %s\n", msg)
	}
	
	// Generate a key pair for the university registrar
	fmt.Println("\nGenerating university registrar key pair...")
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
	
	// Sign the academic credential with all attributes
	fmt.Println("University registrar signing credential...")
	signature, err := bbs.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
	if err != nil {
		log.Fatalf("Failed to sign credential: %v", err)
	}
	fmt.Println("Academic credential signed successfully!")
	
	// Scenario 1: Job application - basic degree verification
	fmt.Println("\n💼 SCENARIO 1: Job Application - Basic Degree Verification 💼")
	fmt.Println("Requirements: Verify name, university, degree and graduation date")
	jobIndices := []int{0, 2, 3, 7} // Name, university, degree, graduation date
	
	jobProof, jobDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		jobIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create job application proof: %v", err)
	}
	
	// Verify job application proof
	err = bbs.VerifyProof(keyPair.PublicKey, jobProof, jobDisclosed, nil)
	if err != nil {
		log.Fatalf("Job application proof verification failed: %v", err)
	}
	
	// Display disclosed attributes for job application
	fmt.Println("Disclosed attributes for job application:")
	for _, idx := range jobIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("Job application proof verified successfully!")
	
	// Scenario 2: Graduate school application - detailed academic record
	fmt.Println("\n🎓 SCENARIO 2: Graduate School Application 🎓")
	fmt.Println("Requirements: Full academic record including GPA and honors")
	gradSchoolIndices := []int{0, 2, 3, 4, 5, 6, 7, 8} // All except ID and transcript hash
	
	gradSchoolProof, gradSchoolDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		gradSchoolIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create graduate school application proof: %v", err)
	}
	
	// Verify graduate school application proof
	err = bbs.VerifyProof(keyPair.PublicKey, gradSchoolProof, gradSchoolDisclosed, nil)
	if err != nil {
		log.Fatalf("Graduate school application proof verification failed: %v", err)
	}
	
	// Display disclosed attributes for graduate school application
	fmt.Println("Disclosed attributes for graduate school application:")
	for _, idx := range gradSchoolIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("Graduate school application proof verified successfully!")
	
	// Scenario 3: Academic transcript verification (with complete details)
	fmt.Println("\n📋 SCENARIO 3: Complete Transcript Verification 📋")
	fmt.Println("Requirements: Complete academic record for official verification")
	transcriptIndices := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9} // All attributes
	
	transcriptProof, transcriptDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		transcriptIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create transcript verification proof: %v", err)
	}
	
	// Verify transcript verification proof
	err = bbs.VerifyProof(keyPair.PublicKey, transcriptProof, transcriptDisclosed, nil)
	if err != nil {
		log.Fatalf("Transcript verification proof failed: %v", err)
	}
	
	// Display disclosed attributes for transcript verification
	fmt.Println("Disclosed attributes for transcript verification:")
	for _, idx := range transcriptIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("Transcript verification proof verified successfully!")
	
	// Scenario 4: Scholarship application - basic details plus GPA and honors
	fmt.Println("\n🏆 SCENARIO 4: Scholarship Application 🏆")
	fmt.Println("Requirements: Basic details plus GPA and honors status")
	scholarshipIndices := []int{0, 2, 3, 4, 6, 8} // Name, university, degree, major, GPA, honors
	
	scholarshipProof, scholarshipDisclosed, err := bbs.CreateProof(
		keyPair.PublicKey,
		signature,
		messages,
		scholarshipIndices,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create scholarship application proof: %v", err)
	}
	
	// Verify scholarship application proof
	err = bbs.VerifyProof(keyPair.PublicKey, scholarshipProof, scholarshipDisclosed, nil)
	if err != nil {
		log.Fatalf("Scholarship application proof verification failed: %v", err)
	}
	
	// Display disclosed attributes for scholarship application
	fmt.Println("Disclosed attributes for scholarship application:")
	for _, idx := range scholarshipIndices {
		fmt.Printf("  - %s\n", messageStrings[idx])
	}
	fmt.Println("Scholarship application proof verified successfully!")
	
	fmt.Println("\nAcademic credential example completed successfully!")
}