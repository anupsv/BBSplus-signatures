//go:build js && wasm

// Package main provides WebAssembly bindings for the BBS+ library
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"syscall/js"

	"github.com/anupsv/bbsplus-signatures/bbs"
)

// Initialize WASM bindings
func Initialize() {
	js.Global().Set("BBS", js.ValueOf(
		map[string]interface{}{
			"version":         js.FuncOf(Version),
			"generateKeyPair": js.FuncOf(GenerateKeyPair),
			"sign":            js.FuncOf(Sign),
			"verify":          js.FuncOf(Verify),
			"createProof":     js.FuncOf(CreateProof),
			"verifyProof":     js.FuncOf(VerifyProof),
		},
	))
}

// Version returns the version information
func Version(this js.Value, args []js.Value) interface{} {
	return js.ValueOf(map[string]interface{}{
		"version":   "1.0.0",
		"buildDate": "2025-04-16",
		"commit":    "BBS+ Library WebAssembly Build",
	})
}

// GenerateKeyPair generates a BBS+ key pair
func GenerateKeyPair(this js.Value, args []js.Value) interface{} {
	// Check arguments (messageCount is optional, defaults to 5)
	messageCount := 5
	if len(args) > 0 && args[0].Type() == js.TypeNumber {
		messageCount = args[0].Int()
	}

	// Generate key pair
	keyPair, err := bbs.GenerateKeyPair(messageCount, rand.Reader)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to generate key pair: %v", err))
	}

	// Serialize private key to bytes
	privKeyBytes := bbs.SerializePrivateKey(keyPair.PrivateKey)
	privKeyHex := hex.EncodeToString(privKeyBytes)

	// Serialize public key to bytes
	pubKeyBytes := bbs.SerializePublicKey(keyPair.PublicKey)
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	// Return as JS object
	return js.ValueOf(map[string]interface{}{
		"success":      true,
		"privateKey":   privKeyHex,
		"publicKey":    pubKeyHex,
		"messageCount": messageCount,
	})
}

// Sign creates a BBS+ signature
func Sign(this js.Value, args []js.Value) interface{} {
	// Validate input
	if len(args) < 3 {
		return errorResponse("Sign requires privateKey, publicKey, and messages")
	}

	// Parse private key from hex
	privKeyHex := args[0].String()
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return errorResponse(fmt.Sprintf("Invalid private key format: %v", err))
	}
	privKey, err := bbs.DeserializePrivateKey(privKeyBytes)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to deserialize private key: %v", err))
	}

	// Parse public key from hex
	pubKeyHex := args[1].String()
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return errorResponse(fmt.Sprintf("Invalid public key format: %v", err))
	}
	pubKey, err := bbs.DeserializePublicKey(pubKeyBytes)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to deserialize public key: %v", err))
	}

	// Parse messages
	if args[2].Type() != js.TypeObject {
		return errorResponse("Messages parameter must be an object with messages array")
	}

	messagesObj := args[2]
	if !messagesObj.Get("messages").Truthy() {
		return errorResponse("Messages parameter must contain messages array")
	}

	messagesJS := messagesObj.Get("messages")
	if messagesJS.Type() != js.TypeObject || messagesJS.Length() == 0 {
		return errorResponse("Messages must be a non-empty array")
	}

	// Convert string messages to field elements
	messages := make([]*big.Int, messagesJS.Length())
	for i := 0; i < messagesJS.Length(); i++ {
		msgStr := messagesJS.Index(i).String()
		msgBytes := bbs.MessageToBytes(msgStr)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
	}

	// Create signature
	signature, err := bbs.Sign(privKey, pubKey, messages, nil)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to create signature: %v", err))
	}

	// Serialize signature to bytes
	sigBytes := bbs.SerializeSignature(signature)
	sigHex := hex.EncodeToString(sigBytes)

	// Return as JS object
	return js.ValueOf(map[string]interface{}{
		"success":   true,
		"signature": sigHex,
	})
}

// Verify verifies a BBS+ signature
func Verify(this js.Value, args []js.Value) interface{} {
	// Validate input
	if len(args) < 3 {
		return errorResponse("Verify requires publicKey, signature, and messages")
	}

	// Parse public key from hex
	pubKeyHex := args[0].String()
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return errorResponse(fmt.Sprintf("Invalid public key format: %v", err))
	}
	pubKey, err := bbs.DeserializePublicKey(pubKeyBytes)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to deserialize public key: %v", err))
	}

	// Parse signature from hex
	sigHex := args[1].String()
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return errorResponse(fmt.Sprintf("Invalid signature format: %v", err))
	}
	signature, err := bbs.DeserializeSignature(sigBytes)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to deserialize signature: %v", err))
	}

	// Parse messages
	if args[2].Type() != js.TypeObject {
		return errorResponse("Messages parameter must be an object with messages array")
	}

	messagesObj := args[2]
	if !messagesObj.Get("messages").Truthy() {
		return errorResponse("Messages parameter must contain messages array")
	}

	messagesJS := messagesObj.Get("messages")
	if messagesJS.Type() != js.TypeObject || messagesJS.Length() == 0 {
		return errorResponse("Messages must be a non-empty array")
	}

	// Convert string messages to field elements
	messages := make([]*big.Int, messagesJS.Length())
	for i := 0; i < messagesJS.Length(); i++ {
		msgStr := messagesJS.Index(i).String()
		msgBytes := bbs.MessageToBytes(msgStr)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
	}

	// Verify signature
	err = bbs.Verify(pubKey, signature, messages, nil)
	if err != nil {
		return js.ValueOf(map[string]interface{}{
			"success": true,
			"valid":   false,
			"error":   err.Error(),
		})
	}

	// Return as JS object
	return js.ValueOf(map[string]interface{}{
		"success": true,
		"valid":   true,
	})
}

// CreateProof creates a BBS+ proof of knowledge
func CreateProof(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 || args[0].Type() != js.TypeObject {
		return errorResponse("CreateProof requires a proof request object")
	}

	proofRequest := args[0]

	// Parse public key from hex
	pubKeyHex := proofRequest.Get("publicKey").String()
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return errorResponse(fmt.Sprintf("Invalid public key format: %v", err))
	}
	pubKey, err := bbs.DeserializePublicKey(pubKeyBytes)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to deserialize public key: %v", err))
	}

	// Parse signature from hex
	sigHex := proofRequest.Get("signature").String()
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return errorResponse(fmt.Sprintf("Invalid signature format: %v", err))
	}
	signature, err := bbs.DeserializeSignature(sigBytes)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to deserialize signature: %v", err))
	}

	// Parse messages
	messagesJS := proofRequest.Get("messages")
	if messagesJS.Type() != js.TypeObject || messagesJS.Length() == 0 {
		return errorResponse("Messages must be a non-empty array")
	}

	// Convert string messages to field elements
	messages := make([]*big.Int, messagesJS.Length())
	for i := 0; i < messagesJS.Length(); i++ {
		msgStr := messagesJS.Index(i).String()
		msgBytes := bbs.MessageToBytes(msgStr)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
	}

	// Parse disclosed indices
	indicesJS := proofRequest.Get("disclosedIndices")
	if indicesJS.Type() != js.TypeObject || indicesJS.Length() == 0 {
		return errorResponse("disclosedIndices must be a non-empty array")
	}

	disclosedIndices := make([]int, indicesJS.Length())
	for i := 0; i < indicesJS.Length(); i++ {
		disclosedIndices[i] = indicesJS.Index(i).Int()
	}

	// Create proof
	proof, disclosedMsgs, err := bbs.CreateProof(
		pubKey,
		signature,
		messages,
		disclosedIndices,
		nil,
	)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to create proof: %v", err))
	}

	// Serialize proof to bytes
	proofBytes := bbs.SerializeProof(proof)
	proofHex := hex.EncodeToString(proofBytes)

	// Build disclosed messages map
	disclosedMsgsMap := make(map[string]string)
	for i, idx := range disclosedIndices {
		disclosedMsgsMap[fmt.Sprintf("%d", idx)] = disclosedMsgs[i].String()
	}

	// Return as JS object
	return js.ValueOf(map[string]interface{}{
		"success":           true,
		"proof":             proofHex,
		"disclosedMessages": disclosedMsgsMap,
	})
}

// VerifyProof verifies a BBS+ proof of knowledge
func VerifyProof(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 || args[0].Type() != js.TypeObject {
		return errorResponse("VerifyProof requires a verification request object")
	}

	verifyRequest := args[0]

	// Parse public key from hex
	pubKeyHex := verifyRequest.Get("publicKey").String()
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return errorResponse(fmt.Sprintf("Invalid public key format: %v", err))
	}
	pubKey, err := bbs.DeserializePublicKey(pubKeyBytes)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to deserialize public key: %v", err))
	}

	// Parse proof from hex
	proofHex := verifyRequest.Get("proof").String()
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return errorResponse(fmt.Sprintf("Invalid proof format: %v", err))
	}
	proof, err := bbs.DeserializeProof(proofBytes)
	if err != nil {
		return errorResponse(fmt.Sprintf("Failed to deserialize proof: %v", err))
	}

	// Parse disclosed messages
	disclosedMsgsJS := verifyRequest.Get("disclosedMessages")
	if disclosedMsgsJS.Type() != js.TypeObject {
		return errorResponse("disclosedMessages must be an object")
	}

	// Get keys from disclosedMessages object
	keys := js.Global().Get("Object").Call("keys", disclosedMsgsJS)

	// Convert to map of index -> big.Int
	disclosedMsgs := make(map[int]*big.Int)
	for i := 0; i < keys.Length(); i++ {
		key := keys.Index(i).String()
		valueStr := disclosedMsgsJS.Get(key).String()

		// Parse index
		index := 0
		fmt.Sscanf(key, "%d", &index)

		// Parse value
		value := new(big.Int)
		_, ok := value.SetString(valueStr, 10)
		if !ok {
			return errorResponse(fmt.Sprintf("Invalid disclosed message value: %s", valueStr))
		}

		disclosedMsgs[index] = value
	}

	// Verify proof
	err = bbs.VerifyProof(pubKey, proof, disclosedMsgs, nil)
	if err != nil {
		return js.ValueOf(map[string]interface{}{
			"success":  true,
			"verified": false,
			"error":    err.Error(),
		})
	}

	// Return as JS object
	return js.ValueOf(map[string]interface{}{
		"success":  true,
		"verified": true,
	})
}

// Helper function to create error responses
func errorResponse(message string) interface{} {
	return js.ValueOf(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
