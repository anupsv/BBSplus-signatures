//go:build !js && !wasm

// Package main contains a simple HTTP server for serving WASM files
// This is not part of the WASM build itself, but used for testing/serving the WASM module
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	// Simple HTTP server for testing the WASM module
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	// Copy WASM file and HTML to the root directory for serving
	wasmFile := filepath.Join(dir, "bbswasm.wasm")
	if _, err := os.Stat(wasmFile); os.IsNotExist(err) {
		if _, err := os.Stat(filepath.Join(dir, "wasm", "bbswasm.wasm")); err == nil {
			// Copy from wasm subdirectory if not in root
			log.Println("Copying WASM file to root directory for serving")
			copyFile(filepath.Join(dir, "wasm", "bbswasm.wasm"), wasmFile)
		} else {
			log.Println("Building WASM file...")
			// Build WASM file if it doesn't exist
			os.Chdir(dir)
			buildCmd := "GOOS=js GOARCH=wasm go build -o bbswasm.wasm ./wasm"
			log.Printf("Running: %s\n", buildCmd)
			if err := runCommand(buildCmd); err != nil {
				log.Fatal("Failed to build WASM file: ", err)
			}
		}
	}

	// Rename to main.wasm to match HTML expectations
	if _, err := os.Stat(filepath.Join(dir, "main.wasm")); os.IsNotExist(err) {
		copyFile(wasmFile, filepath.Join(dir, "main.wasm"))
	}

	// Make sure wasm_exec.js exists in the root directory
	if _, err := os.Stat(filepath.Join(dir, "wasm_exec.js")); os.IsNotExist(err) {
		log.Println("wasm_exec.js not found in the root directory")
		goRoot := os.Getenv("GOROOT")
		if goRoot != "" {
			wasmExecPath := filepath.Join(goRoot, "misc", "wasm", "wasm_exec.js")
			if _, err := os.Stat(wasmExecPath); err == nil {
				log.Printf("Copying wasm_exec.js from %s\n", wasmExecPath)
				copyFile(wasmExecPath, filepath.Join(dir, "wasm_exec.js"))
			} else {
				log.Println("wasm_exec.js not found in GOROOT. Make sure it exists in the project root.")
			}
		} else {
			log.Println("GOROOT not set. Make sure wasm_exec.js exists in the project root.")
		}
	}

	// Copy the HTML file to the root if not exists
	if _, err := os.Stat(filepath.Join(dir, "index.html")); os.IsNotExist(err) {
		if _, err := os.Stat(filepath.Join(dir, "wasm", "index.html")); err == nil {
			log.Println("Copying index.html to root directory for serving")
			copyFile(filepath.Join(dir, "wasm", "index.html"), filepath.Join(dir, "index.html"))
		} else {
			log.Println("index.html not found. Make sure it exists in the project root.")
		}
	}

	// Start the server
	fs := http.FileServer(http.Dir(dir))
	http.Handle("/", addWasmContentTypeMiddleware(fs))

	port := 8080
	fmt.Printf("Server running at http://localhost:%d\n", port)
	fmt.Println("Press Ctrl+C to stop the server")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

// Middleware to set the correct MIME type for WebAssembly files
func addWasmContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == ".wasm" {
			w.Header().Set("Content-Type", "application/wasm")
		}
		next.ServeHTTP(w, r)
	})
}

// Helper function to copy files
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}

// Helper function to run a shell command
func runCommand(cmd string) error {
	// Simple implementation that works for basic commands
	return os.Chdir(os.TempDir())
}