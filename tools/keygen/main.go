package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/asv/bbs/bbs"
)

func main() {
	// Define command-line flags
	messageCount := flag.Int("messages", 5, "Number of messages to support")
	outputFile := flag.String("output", "", "Output file for key pair (optional)")
	flag.Parse()

	// Generate key pair
	fmt.Printf("Generating BBS+ key pair for %d messages...\n", *messageCount)
	keyPair, err := bbs.GenerateKeyPair(*messageCount, rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
		os.Exit(1)
	}

	// Create serializable format
	serialized := struct {
		PrivateKey    string `json:"privateKey"`
		PublicKey     string `json:"publicKey"`
		MessageCount  int    `json:"messageCount"`
	}{
		PrivateKey:    base64.StdEncoding.EncodeToString(keyPair.PrivateKey.Value.Bytes()),
		PublicKey:     "PLACEHOLDER", // In a real implementation, we would serialize the public key
		MessageCount:  keyPair.MessageCount,
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(serialized, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing key pair: %v\n", err)
		os.Exit(1)
	}

	// Write to file or stdout
	if *outputFile != "" {
		err = os.WriteFile(*outputFile, jsonData, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Key pair written to %s\n", *outputFile)
	} else {
		fmt.Println(string(jsonData))
	}
}