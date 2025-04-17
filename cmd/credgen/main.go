// Command credgen is a utility for working with BBS+ credentials
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/asv/bbs/bbs"
)

// Command represents a subcommand
type Command struct {
	Name        string
	Description string
	Execute     func(args []string) error
}

// Credential represents a BBS+ credential
type Credential struct {
	Schema      string            `json:"schema"`
	PublicKey   string            `json:"publicKey"`
	Signature   string            `json:"signature"`
	Messages    map[string]string `json:"messages"`
	DateIssued  string            `json:"dateIssued"`
	DateExpires string            `json:"dateExpires,omitempty"`
	Issuer      string            `json:"issuer"`
}

// CredentialProof represents a selective disclosure proof for a credential
type CredentialProof struct {
	Schema           string            `json:"schema"`
	PublicKey        string            `json:"publicKey"`
	Proof            string            `json:"proof"`
	DisclosedMessages map[string]string `json:"disclosedMessages"`
	DateGenerated    string            `json:"dateGenerated"`
	Issuer           string            `json:"issuer"`
}

func main() {
	// Define available commands
	commands := []Command{
		{
			Name:        "keygen",
			Description: "Generate a new BBS+ key pair",
			Execute:     cmdKeyGen,
		},
		{
			Name:        "issue",
			Description: "Issue a new credential",
			Execute:     cmdIssueCredential,
		},
		{
			Name:        "verify",
			Description: "Verify a credential",
			Execute:     cmdVerifyCredential,
		},
		{
			Name:        "prove",
			Description: "Create a selective disclosure proof",
			Execute:     cmdCreateProof,
		},
		{
			Name:        "verify-proof",
			Description: "Verify a selective disclosure proof",
			Execute:     cmdVerifyProof,
		},
	}
	
	// Show help if no command provided
	if len(os.Args) < 2 {
		showHelp(commands)
		os.Exit(1)
	}
	
	// Find and execute the requested command
	cmdName := os.Args[1]
	for _, cmd := range commands {
		if cmd.Name == cmdName {
			err := cmd.Execute(os.Args[2:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	
	// Command not found
	fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmdName)
	showHelp(commands)
	os.Exit(1)
}

// Display help information
func showHelp(commands []Command) {
	fmt.Println("BBS+ Credential Generator - Utility for issuing and verifying BBS+ credentials")
	fmt.Println("\nUsage:")
	fmt.Println("  credgen <command> [options]")
	
	fmt.Println("\nAvailable Commands:")
	for _, cmd := range commands {
		fmt.Printf("  %-12s %s\n", cmd.Name, cmd.Description)
	}
	
	fmt.Println("\nRun 'credgen <command> -h' for more information about a command")
}

// Generate key pair command
func cmdKeyGen(args []string) error {
	// Parse flags
	flagSet := flag.NewFlagSet("keygen", flag.ExitOnError)
	attributeCount := flagSet.Int("attributes", 10, "Number of attributes/messages in the credential")
	outputFile := flagSet.String("output", "keypair.json", "Output file for the key pair")
	flagSet.Parse(args)
	
	if *attributeCount < 1 {
		return fmt.Errorf("attribute count must be at least 1")
	}
	
	// Generate key pair
	fmt.Printf("Generating key pair for %d attributes...\n", *attributeCount)
	keyPair, err := bbs.GenerateKeyPair(*attributeCount, rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}
	
	// Serialize private key
	privKeyBytes, err := keyPair.PrivateKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to serialize private key: %w", err)
	}
	
	// Serialize public key
	pubKeyBytes, err := keyPair.PublicKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to serialize public key: %w", err)
	}
	
	// Create JSON output
	output := struct {
		AttributeCount int    `json:"attributeCount"`
		PrivateKey     string `json:"privateKey"`
		PublicKey      string `json:"publicKey"`
	}{
		AttributeCount: *attributeCount,
		PrivateKey:     base64.StdEncoding.EncodeToString(privKeyBytes),
		PublicKey:      base64.StdEncoding.EncodeToString(pubKeyBytes),
	}
	
	// Save to file
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key pair to JSON: %w", err)
	}
	
	err = ioutil.WriteFile(*outputFile, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write key pair to file: %w", err)
	}
	
	fmt.Printf("Key pair generated and saved to %s\n", *outputFile)
	return nil
}

// Issue credential command
func cmdIssueCredential(args []string) error {
	// Parse flags
	flagSet := flag.NewFlagSet("issue", flag.ExitOnError)
	keyFile := flagSet.String("key", "keypair.json", "Key pair file")
	schemaFile := flagSet.String("schema", "", "Schema file for the credential attributes")
	attributesFile := flagSet.String("attributes", "", "JSON file containing attribute values")
	outputFile := flagSet.String("output", "credential.json", "Output file for the credential")
	issuer := flagSet.String("issuer", "BBS+ Test Issuer", "Issuer identifier")
	flagSet.Parse(args)
	
	// Load key pair
	keyPairData, err := ioutil.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key pair file: %w", err)
	}
	
	var keyPairJson struct {
		AttributeCount int    `json:"attributeCount"`
		PrivateKey     string `json:"privateKey"`
		PublicKey      string `json:"publicKey"`
	}
	
	err = json.Unmarshal(keyPairData, &keyPairJson)
	if err != nil {
		return fmt.Errorf("failed to parse key pair JSON: %w", err)
	}
	
	// Decode private key
	privKeyBytes, err := base64.StdEncoding.DecodeString(keyPairJson.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}
	
	privateKey := &bbs.PrivateKey{}
	err = privateKey.UnmarshalBinary(privKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal private key: %w", err)
	}
	
	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(keyPairJson.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}
	
	publicKey := &bbs.PublicKey{}
	err = publicKey.UnmarshalBinary(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	
	// Load schema if provided
	var schemaJson map[string]interface{}
	if *schemaFile != "" {
		schemaData, err := ioutil.ReadFile(*schemaFile)
		if err != nil {
			return fmt.Errorf("failed to read schema file: %w", err)
		}
		
		err = json.Unmarshal(schemaData, &schemaJson)
		if err != nil {
			return fmt.Errorf("failed to parse schema JSON: %w", err)
		}
	}
	
	// Load attributes
	if *attributesFile == "" {
		return fmt.Errorf("attributes file is required")
	}
	
	attributesData, err := ioutil.ReadFile(*attributesFile)
	if err != nil {
		return fmt.Errorf("failed to read attributes file: %w", err)
	}
	
	var attributesJson map[string]string
	err = json.Unmarshal(attributesData, &attributesJson)
	if err != nil {
		return fmt.Errorf("failed to parse attributes JSON: %w", err)
	}
	
	// Check attribute count
	if len(attributesJson) != keyPairJson.AttributeCount {
		return fmt.Errorf("attribute count mismatch: key supports %d attributes, but %d provided",
			keyPairJson.AttributeCount, len(attributesJson))
	}
	
	// Create ordered list of attributes
	attributeNames := make([]string, 0, len(attributesJson))
	for name := range attributesJson {
		attributeNames = append(attributeNames, name)
	}
	
	// Sort attribute names for deterministic ordering
	sort.Strings(attributeNames)
	
	// Convert attributes to messages
	messages := make([]*big.Int, len(attributeNames))
	for i, name := range attributeNames {
		value := attributesJson[name]
		msgBytes := bbs.MessageToBytes(value)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
	}
	
	// Sign messages
	signature, err := bbs.Sign(privateKey, publicKey, messages, nil)
	if err != nil {
		return fmt.Errorf("failed to sign messages: %w", err)
	}
	
	// Serialize signature
	signatureBytes, err := signature.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to serialize signature: %w", err)
	}
	
	// Create credential
	now := time.Now().Format(time.RFC3339)
	credential := Credential{
		Schema:      *schemaFile,
		PublicKey:   keyPairJson.PublicKey,
		Signature:   base64.StdEncoding.EncodeToString(signatureBytes),
		Messages:    attributesJson,
		DateIssued:  now,
		Issuer:      *issuer,
	}
	
	// Save credential to file
	credentialData, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credential to JSON: %w", err)
	}
	
	err = ioutil.WriteFile(*outputFile, credentialData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write credential to file: %w", err)
	}
	
	fmt.Printf("Credential issued and saved to %s\n", *outputFile)
	return nil
}

// Verify credential command
func cmdVerifyCredential(args []string) error {
	// Parse flags
	flagSet := flag.NewFlagSet("verify", flag.ExitOnError)
	credentialFile := flagSet.String("credential", "credential.json", "Credential file to verify")
	flagSet.Parse(args)
	
	// Load credential
	credentialData, err := ioutil.ReadFile(*credentialFile)
	if err != nil {
		return fmt.Errorf("failed to read credential file: %w", err)
	}
	
	var credential Credential
	err = json.Unmarshal(credentialData, &credential)
	if err != nil {
		return fmt.Errorf("failed to parse credential JSON: %w", err)
	}
	
	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(credential.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}
	
	publicKey := &bbs.PublicKey{}
	err = publicKey.UnmarshalBinary(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	
	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(credential.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	
	signature := &bbs.Signature{}
	err = signature.UnmarshalBinary(signatureBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal signature: %w", err)
	}
	
	// Get attribute names and sort them
	attributeNames := make([]string, 0, len(credential.Messages))
	for name := range credential.Messages {
		attributeNames = append(attributeNames, name)
	}
	sort.Strings(attributeNames)
	
	// Convert attributes to messages
	messages := make([]*big.Int, len(attributeNames))
	for i, name := range attributeNames {
		value := credential.Messages[name]
		msgBytes := bbs.MessageToBytes(value)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
	}
	
	// Verify signature
	err = bbs.Verify(publicKey, signature, messages, nil)
	if err != nil {
		return fmt.Errorf("credential verification failed: %w", err)
	}
	
	fmt.Println("Credential verified successfully!")
	return nil
}

// Create proof command
func cmdCreateProof(args []string) error {
	// Parse flags
	flagSet := flag.NewFlagSet("prove", flag.ExitOnError)
	credentialFile := flagSet.String("credential", "credential.json", "Credential file")
	disclosedAttrs := flagSet.String("disclose", "", "Comma-separated list of attribute names to disclose")
	outputFile := flagSet.String("output", "proof.json", "Output file for the proof")
	flagSet.Parse(args)
	
	// Load credential
	credentialData, err := ioutil.ReadFile(*credentialFile)
	if err != nil {
		return fmt.Errorf("failed to read credential file: %w", err)
	}
	
	var credential Credential
	err = json.Unmarshal(credentialData, &credential)
	if err != nil {
		return fmt.Errorf("failed to parse credential JSON: %w", err)
	}
	
	// Parse disclosed attributes
	if *disclosedAttrs == "" {
		return fmt.Errorf("at least one attribute must be disclosed")
	}
	
	disclosedNames := strings.Split(*disclosedAttrs, ",")
	for i := range disclosedNames {
		disclosedNames[i] = strings.TrimSpace(disclosedNames[i])
	}
	
	// Validate disclosed attributes
	for _, name := range disclosedNames {
		if _, ok := credential.Messages[name]; !ok {
			return fmt.Errorf("attribute '%s' not found in credential", name)
		}
	}
	
	// Get all attribute names and sort them
	attributeNames := make([]string, 0, len(credential.Messages))
	for name := range credential.Messages {
		attributeNames = append(attributeNames, name)
	}
	sort.Strings(attributeNames)
	
	// Map attribute names to indices
	nameToIndex := make(map[string]int)
	for i, name := range attributeNames {
		nameToIndex[name] = i
	}
	
	// Get indices of disclosed attributes
	disclosedIndices := make([]int, len(disclosedNames))
	for i, name := range disclosedNames {
		disclosedIndices[i] = nameToIndex[name]
	}
	
	// Convert attributes to messages
	messages := make([]*big.Int, len(attributeNames))
	for i, name := range attributeNames {
		value := credential.Messages[name]
		msgBytes := bbs.MessageToBytes(value)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
	}
	
	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(credential.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}
	
	publicKey := &bbs.PublicKey{}
	err = publicKey.UnmarshalBinary(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	
	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(credential.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	
	signature := &bbs.Signature{}
	err = signature.UnmarshalBinary(signatureBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal signature: %w", err)
	}
	
	// Create proof
	proof, _, err := bbs.CreateProof(publicKey, signature, messages, disclosedIndices, nil)
	if err != nil {
		return fmt.Errorf("failed to create proof: %w", err)
	}
	
	// Serialize proof
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to serialize proof: %w", err)
	}
	
	// Create disclosed messages map with attribute names
	disclosedMessages := make(map[string]string)
	for i := range disclosedIndices {
		name := disclosedNames[i]
		value := credential.Messages[name]
		disclosedMessages[name] = value
	}
	
	// Create proof object
	now := time.Now().Format(time.RFC3339)
	credentialProof := CredentialProof{
		Schema:           credential.Schema,
		PublicKey:        credential.PublicKey,
		Proof:            base64.StdEncoding.EncodeToString(proofBytes),
		DisclosedMessages: disclosedMessages,
		DateGenerated:    now,
		Issuer:           credential.Issuer,
	}
	
	// Save proof to file
	proofData, err := json.MarshalIndent(credentialProof, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal proof to JSON: %w", err)
	}
	
	err = ioutil.WriteFile(*outputFile, proofData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write proof to file: %w", err)
	}
	
	fmt.Printf("Proof created and saved to %s\n", *outputFile)
	fmt.Println("Disclosed attributes:")
	for name, value := range disclosedMessages {
		fmt.Printf("  %s: %s\n", name, value)
	}
	
	return nil
}

// Verify proof command
func cmdVerifyProof(args []string) error {
	// Parse flags
	flagSet := flag.NewFlagSet("verify-proof", flag.ExitOnError)
	proofFile := flagSet.String("proof", "proof.json", "Proof file to verify")
	flagSet.Parse(args)
	
	// Load proof
	proofData, err := ioutil.ReadFile(*proofFile)
	if err != nil {
		return fmt.Errorf("failed to read proof file: %w", err)
	}
	
	var credentialProof CredentialProof
	err = json.Unmarshal(proofData, &credentialProof)
	if err != nil {
		return fmt.Errorf("failed to parse proof JSON: %w", err)
	}
	
	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(credentialProof.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}
	
	publicKey := &bbs.PublicKey{}
	err = publicKey.UnmarshalBinary(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	
	// Decode proof
	proofBytes, err := base64.StdEncoding.DecodeString(credentialProof.Proof)
	if err != nil {
		return fmt.Errorf("failed to decode proof: %w", err)
	}
	
	proof := &bbs.ProofOfKnowledge{}
	err = proof.UnmarshalBinary(proofBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal proof: %w", err)
	}
	
	// Get attribute names and sort them
	disclosedNames := make([]string, 0, len(credentialProof.DisclosedMessages))
	for name := range credentialProof.DisclosedMessages {
		disclosedNames = append(disclosedNames, name)
	}
	sort.Strings(disclosedNames)
	
	// Convert disclosed messages to map[int]*big.Int
	// Use indices starting from 0 for disclosed messages
	disclosedMsgs := make(map[int]*big.Int)
	for i, name := range disclosedNames {
		value := credentialProof.DisclosedMessages[name]
		msgBytes := bbs.MessageToBytes(value)
		disclosedMsgs[i] = bbs.MessageToFieldElement(msgBytes)
	}
	
	// Verify proof
	err = bbs.VerifyProof(publicKey, proof, disclosedMsgs, nil)
	if err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}
	
	fmt.Println("Proof verified successfully!")
	fmt.Println("Disclosed attributes:")
	for name, value := range credentialProof.DisclosedMessages {
		fmt.Printf("  %s: %s\n", name, value)
	}
	
	return nil
}