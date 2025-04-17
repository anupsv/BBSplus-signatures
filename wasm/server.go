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