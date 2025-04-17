// Package wasm provides WebAssembly bindings for the BBS+ library.
//
// This package enables the BBS+ library to be used in web browsers and other
// JavaScript environments via WebAssembly. It provides wrapper functions that
// handle the conversion between Go and JavaScript data structures.
//
// Main functionality:
// - JavaScript-friendly API for BBS+ operations
// - Type conversion between Go and JavaScript
// - Browser-compatible error handling
// - Memory management for WASM context
//
// This package is used by the WASM build target and is not intended to be
// imported directly in Go applications.
//
// JavaScript Example Usage:
//
//     // Generate a key pair
//     const keyPair = generateKeyPair(5);
//     
//     // Sign messages
//     const signature = sign(keyPair.privateKey, keyPair.publicKey, {
//         messages: ["message1", "message2", "message3", "message4", "message5"]
//     });
//     
//     // Create proof
//     const proof = createProof({
//         messages: ["message1", "message2", "message3", "message4", "message5"],
//         disclosedIndices: [0, 2],
//         signature: signature.signature,
//         publicKey: keyPair.publicKey
//     });
package wasm

// Constants for WASM integration
const (
	// MaxInputSize is the maximum allowed size of JS inputs
	MaxInputSize = 10 * 1024 * 1024 // 10MB
	
	// MaxMessagesPerCredential is the maximum number of messages in a credential
	MaxMessagesPerCredential = 100
)