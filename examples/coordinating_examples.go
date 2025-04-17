// Package main provides examples for the BBS+ library
package main

import (
	"fmt"
	"os"
)

// Different examples to run
type Example struct {
	Name        string
	Description string
	Run         func()
}

// Available examples
var examples = []Example{
	{
		Name:        "basic",
		Description: "Basic BBS+ operations (sign, verify, proof)",
		Run:         RunExample,
	},
	{
		Name:        "migration",
		Description: "Migration from old package to new package structure",
		Run:         RunMigrationExample,
	},
}

func main() {
	// If no arguments, show help
	if len(os.Args) < 2 {
		showHelp()
		return
	}

	// Get the example name
	exampleName := os.Args[1]

	// Run the example
	for _, example := range examples {
		if example.Name == exampleName {
			example.Run()
			return
		}
	}

	// Example not found
	fmt.Printf("Example '%s' not found\n\n", exampleName)
	showHelp()
}

// showHelp displays usage information
func showHelp() {
	fmt.Println("BBS+ Examples")
	fmt.Println("============")
	fmt.Println("Usage: go run examples/coordinating_examples.go <example-name>")
	fmt.Println("\nAvailable examples:")
	
	for _, example := range examples {
		fmt.Printf("  %-12s %s\n", example.Name, example.Description)
	}
}