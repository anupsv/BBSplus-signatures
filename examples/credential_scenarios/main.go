// Main entry point for running credential example scenarios
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// Define command-line flags for selecting scenarios
	simpleFlag := flag.Bool("simple", false, "Run the simple BBS+ example")
	healthcareFlag := flag.Bool("healthcare", false, "Run the healthcare credential example")
	identityFlag := flag.Bool("identity", false, "Run the digital identity example")
	academicFlag := flag.Bool("academic", false, "Run the academic credential example")
	allFlag := flag.Bool("all", false, "Run all credential examples")
	flag.Parse()

	// If no flags provided, show usage information
	if !(*simpleFlag || *healthcareFlag || *identityFlag || *academicFlag || *allFlag) {
		fmt.Println("BBS+ Credential Scenario Examples")
		fmt.Println("=================================")
		fmt.Println("\nPlease specify which scenarios to run with the following flags:")
		flag.PrintDefaults()
		fmt.Println("\nExample: go run . -all")
		os.Exit(0)
	}

	// Run selected examples
	if *simpleFlag || *allFlag {
		RunSimpleExample()
		fmt.Println("\n" + strings.Repeat("-", 80) + "\n")
	}

	if *healthcareFlag || *allFlag {
		RunHealthcareCredentialExample()
		fmt.Println("\n" + strings.Repeat("-", 80) + "\n")
	}

	if *identityFlag || *allFlag {
		RunDigitalIdentityExample()
		fmt.Println("\n" + strings.Repeat("-", 80) + "\n")
	}

	if *academicFlag || *allFlag {
		RunAcademicCredentialExample()
	}

	if *allFlag {
		fmt.Println("\nAll credential scenarios completed successfully!")
	}
}
