package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"syscall/js"

	"github.com/asv/bbs/bbs"
)

// MessageSet represents a set of messages for signing or proving
type MessageSet struct {
	Messages []string `json:"messages"`
}

// ProofRequest represents a request to create a selective disclosure proof
type ProofRequest struct {
	Messages         []string `json:"messages"`
	DisclosedIndices []int    `json:"disclosedIndices"`
	Signature        string   `json:"signature"`
	PublicKey        string   `json:"publicKey"`
}

// VerifyRequest represents a request to verify a proof
type VerifyRequest struct {
	Proof            string            `json:"proof"`
	DisclosedMessages map[string]string `json:"disclosedMessages"`
	PublicKey        string            `json:"publicKey"`
}

// WASM entry point
func main() {
	c := make(chan struct{})
	
	// Register JavaScript functions
	js.Global().Set("generateKeyPair", js.FuncOf(generateKeyPair))
	js.Global().Set("sign", js.FuncOf(sign))
	js.Global().Set("verify", js.FuncOf(verify))
	js.Global().Set("createProof", js.FuncOf(createProof))
	js.Global().Set("verifyProof", js.FuncOf(verifyProof))
	
	// Keep the program running
	<-c
}

// generateKeyPair creates a new BBS+ key pair for the specified number of messages
func generateKeyPair(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return createErrorResponse("Missing messageCount parameter")
	}
	
	messageCount := args[0].Int()
	if messageCount <= 0 {
		return createErrorResponse("messageCount must be positive")
	}
	
	// Generate the key pair
	keyPair, err := bbs.GenerateKeyPair(messageCount, rand.Reader)
	if err != nil {
		return createErrorResponse("Failed to generate key pair: " + err.Error())
	}
	
	// Serialize the key pair
	privateKeyBytes, err := keyPair.PrivateKey.MarshalBinary()
	if err != nil {
		return createErrorResponse("Failed to serialize private key: " + err.Error())
	}
	
	publicKeyBytes, err := keyPair.PublicKey.MarshalBinary()
	if err != nil {
		return createErrorResponse("Failed to serialize public key: " + err.Error())
	}
	
	// Return the serialized key pair
	return map[string]interface{}{
		"success": true,
		"privateKey": base64.StdEncoding.EncodeToString(privateKeyBytes),
		"publicKey": base64.StdEncoding.EncodeToString(publicKeyBytes),
	}
}

// sign creates a BBS+ signature on a set of messages
func sign(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return createErrorResponse("Missing parameters: privateKey, publicKey, messagesJson")
	}
	
	// Parse parameters
	privateKeyB64 := args[0].String()
	publicKeyB64 := args[1].String()
	messagesJson := args[2].String()
	
	// Decode private key
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return createErrorResponse("Failed to decode private key: " + err.Error())
	}
	
	privateKey := &bbs.PrivateKey{}
	err = privateKey.UnmarshalBinary(privateKeyBytes)
	if err != nil {
		return createErrorResponse("Failed to parse private key: " + err.Error())
	}
	
	// Decode public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return createErrorResponse("Failed to decode public key: " + err.Error())
	}
	
	publicKey := &bbs.PublicKey{}
	err = publicKey.UnmarshalBinary(publicKeyBytes)
	if err != nil {
		return createErrorResponse("Failed to parse public key: " + err.Error())
	}
	
	// Parse messages
	var messageSet MessageSet
	err = json.Unmarshal([]byte(messagesJson), &messageSet)
	if err != nil {
		return createErrorResponse("Failed to parse messages: " + err.Error())
	}
	
	// Convert messages to field elements
	messages := make([]*big.Int, len(messageSet.Messages))
	for i, msg := range messageSet.Messages {
		msgBytes := bbs.MessageToBytes(msg)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
	}
	
	// Sign the messages
	signature, err := bbs.Sign(privateKey, publicKey, messages, nil)
	if err != nil {
		return createErrorResponse("Failed to sign messages: " + err.Error())
	}
	
	// Serialize the signature
	signatureBytes, err := signature.MarshalBinary()
	if err != nil {
		return createErrorResponse("Failed to serialize signature: " + err.Error())
	}
	
	// Return the serialized signature
	return map[string]interface{}{
		"success": true,
		"signature": base64.StdEncoding.EncodeToString(signatureBytes),
	}
}

// verify verifies a BBS+ signature on a set of messages
func verify(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return createErrorResponse("Missing parameters: publicKey, signature, messagesJson")
	}
	
	// Parse parameters
	publicKeyB64 := args[0].String()
	signatureB64 := args[1].String()
	messagesJson := args[2].String()
	
	// Decode public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return createErrorResponse("Failed to decode public key: " + err.Error())
	}
	
	publicKey := &bbs.PublicKey{}
	err = publicKey.UnmarshalBinary(publicKeyBytes)
	if err != nil {
		return createErrorResponse("Failed to parse public key: " + err.Error())
	}
	
	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return createErrorResponse("Failed to decode signature: " + err.Error())
	}
	
	signature := &bbs.Signature{}
	err = signature.UnmarshalBinary(signatureBytes)
	if err != nil {
		return createErrorResponse("Failed to parse signature: " + err.Error())
	}
	
	// Parse messages
	var messageSet MessageSet
	err = json.Unmarshal([]byte(messagesJson), &messageSet)
	if err != nil {
		return createErrorResponse("Failed to parse messages: " + err.Error())
	}
	
	// Convert messages to field elements
	messages := make([]*big.Int, len(messageSet.Messages))
	for i, msg := range messageSet.Messages {
		msgBytes := bbs.MessageToBytes(msg)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
	}
	
	// Verify the signature
	err = bbs.Verify(publicKey, signature, messages, nil)
	if err != nil {
		return createErrorResponse("Signature verification failed: " + err.Error())
	}
	
	// Return success
	return map[string]interface{}{
		"success": true,
		"verified": true,
	}
}

// createProof creates a selective disclosure proof
func createProof(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return createErrorResponse("Missing proofRequest parameter")
	}
	
	// Parse parameters
	proofRequestJson := args[0].String()
	
	var proofRequest ProofRequest
	err := json.Unmarshal([]byte(proofRequestJson), &proofRequest)
	if err != nil {
		return createErrorResponse("Failed to parse proof request: " + err.Error())
	}
	
	// Decode public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(proofRequest.PublicKey)
	if err != nil {
		return createErrorResponse("Failed to decode public key: " + err.Error())
	}
	
	publicKey := &bbs.PublicKey{}
	err = publicKey.UnmarshalBinary(publicKeyBytes)
	if err != nil {
		return createErrorResponse("Failed to parse public key: " + err.Error())
	}
	
	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(proofRequest.Signature)
	if err != nil {
		return createErrorResponse("Failed to decode signature: " + err.Error())
	}
	
	signature := &bbs.Signature{}
	err = signature.UnmarshalBinary(signatureBytes)
	if err != nil {
		return createErrorResponse("Failed to parse signature: " + err.Error())
	}
	
	// Convert messages to field elements
	messages := make([]*big.Int, len(proofRequest.Messages))
	for i, msg := range proofRequest.Messages {
		msgBytes := bbs.MessageToBytes(msg)
		messages[i] = bbs.MessageToFieldElement(msgBytes)
	}
	
	// Create proof
	proof, disclosedMsgs, err := bbs.CreateProof(
		publicKey,
		signature,
		messages,
		proofRequest.DisclosedIndices,
		nil,
	)
	if err != nil {
		return createErrorResponse("Failed to create proof: " + err.Error())
	}
	
	// Serialize proof
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		return createErrorResponse("Failed to serialize proof: " + err.Error())
	}
	
	// Convert disclosed messages for response
	disclosedMessages := make(map[string]string)
	for i, msg := range disclosedMsgs {
		disclosedMessages[string(i)] = msg.String()
	}
	
	// Return the proof
	return map[string]interface{}{
		"success": true,
		"proof": base64.StdEncoding.EncodeToString(proofBytes),
		"disclosedMessages": disclosedMessages,
	}
}

// verifyProof verifies a selective disclosure proof
func verifyProof(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return createErrorResponse("Missing verifyRequest parameter")
	}
	
	// Parse parameters
	verifyRequestJson := args[0].String()
	
	var verifyRequest VerifyRequest
	err := json.Unmarshal([]byte(verifyRequestJson), &verifyRequest)
	if err != nil {
		return createErrorResponse("Failed to parse verify request: " + err.Error())
	}
	
	// Decode public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(verifyRequest.PublicKey)
	if err != nil {
		return createErrorResponse("Failed to decode public key: " + err.Error())
	}
	
	publicKey := &bbs.PublicKey{}
	err = publicKey.UnmarshalBinary(publicKeyBytes)
	if err != nil {
		return createErrorResponse("Failed to parse public key: " + err.Error())
	}
	
	// Decode proof
	proofBytes, err := base64.StdEncoding.DecodeString(verifyRequest.Proof)
	if err != nil {
		return createErrorResponse("Failed to decode proof: " + err.Error())
	}
	
	proof := &bbs.ProofOfKnowledge{}
	err = proof.UnmarshalBinary(proofBytes)
	if err != nil {
		return createErrorResponse("Failed to parse proof: " + err.Error())
	}
	
	// Convert disclosed messages
	disclosedMsgs := make(map[int]*big.Int)
	for indexStr, valueStr := range verifyRequest.DisclosedMessages {
		var index int
		err := json.Unmarshal([]byte(indexStr), &index)
		if err != nil {
			return createErrorResponse("Invalid disclosed message index: " + err.Error())
		}
		
		value := new(big.Int)
		if _, ok := value.SetString(valueStr, 10); !ok {
			return createErrorResponse("Invalid disclosed message value: " + valueStr)
		}
		
		disclosedMsgs[index] = value
	}
	
	// Verify proof
	err = bbs.VerifyProof(publicKey, proof, disclosedMsgs, nil)
	if err != nil {
		return createErrorResponse("Proof verification failed: " + err.Error())
	}
	
	// Return success
	return map[string]interface{}{
		"success": true,
		"verified": true,
	}
}

// Helper function to create error responses
func createErrorResponse(message string) map[string]interface{} {
	return map[string]interface{}{
		"success": false,
		"error": message,
	}
}