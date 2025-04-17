// BBS+ Signatures - Main entry point
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	fmt.Println("BBS+ Signatures - A Go implementation with selective disclosure proofs")
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("Example usage can be found in the examples directory:")
	fmt.Println("To run the example: go run examples/main.go")
	fmt.Println()
	fmt.Println("For more information, see README.md")
	
	// Check if the example directory exists
	if _, err := os.Stat("examples"); err == nil {
		// Run the example if no arguments provided
		if len(os.Args) == 1 {
			fmt.Println("\nRunning the basic example...")
			
			// Get the absolute path to the examples directory
			examplesDir, err := filepath.Abs("examples")
			if err != nil {
				fmt.Println("Error getting path to examples:", err)
				return
			}
			
			// Run the main example
			cmd := exec.Command("go", "run", filepath.Join(examplesDir, "main.go"))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			if err != nil {
				fmt.Println("Error running example:", err)
			}
		}
	}
}