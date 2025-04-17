package wasm

import (
	"encoding/json"
	"fmt"
	"math/big"
	"syscall/js"

	"github.com/asv/projects/bbs/pkg/core"
	"github.com/asv/projects/bbs/pkg/proof"
)

// JSValue types for WebAssembly
type JSValue = js.Value
type JSFunc = js.Func

// ErrorResponse is the standard error response format for JS
type ErrorResponse struct {
	Error   bool   `json:"error"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// NewErrorResponse creates a new error response
func NewErrorResponse(err error) map[string]interface{} {
	if err == nil {
		return map[string]interface{}{
			"error": false,
		}
	}

	errCode := "UNKNOWN_ERROR"
	// Map error types to codes
	switch err {
	case core.ErrInvalidSignature:
		errCode = "INVALID_SIGNATURE"
	case core.ErrPairingFailed:
		errCode = "PAIRING_FAILED"
	case core.ErrInvalidMessageCount:
		errCode = "INVALID_MESSAGE_COUNT"
	default:
		// Keep default code
	}

	return map[string]interface{}{
		"error":   true,
		"message": err.Error(),
		"code":    errCode,
	}
}

// KeyPairResponse is the format for key pair data returned to JS
type KeyPairResponse struct {
	PrivateKey    string `json:"privateKey"`
	PublicKey     string `json:"publicKey"`
	MessageCount  int    `json:"messageCount"`
	EncodingError string `json:"encodingError,omitempty"`
}

// SignatureResponse is the format for signature data returned to JS
type SignatureResponse struct {
	Signature     string `json:"signature"`
	EncodingError string `json:"encodingError,omitempty"`
}

// ProofResponse is the format for proof data returned to JS
type ProofResponse struct {
	Proof             string            `json:"proof"`
	DisclosedMessages map[string]string `json:"disclosedMessages"`
	EncodingError     string            `json:"encodingError,omitempty"`
}

// Initialize sets up the WebAssembly bindings
func Initialize() {
	// Set global object
	js.Global().Set("BBS", js.ValueOf(
		map[string]interface{}{
			"generateKeyPair": js.FuncOf(GenerateKeyPair),
			"sign":           js.FuncOf(Sign),
			"verify":         js.FuncOf(Verify),
			"createProof":    js.FuncOf(CreateProof),
			"verifyProof":    js.FuncOf(VerifyProof),
			"version":        js.FuncOf(Version),
		},
	))

	// Prevent program from exiting
	select {}
}

// Version returns the library version
func Version(this js.Value, args []js.Value) interface{} {
	return js.ValueOf(map[string]interface{}{
		"version":   "1.0.0",
		"buildDate": "2025-04-16",
		"commit":    "BBS+ Library WebAssembly Build",
	})
}

// GenerateKeyPair creates a new key pair
func GenerateKeyPair(this js.Value, args []js.Value) interface{} {
	// Validate input
	if len(args) < 1 {
		return js.ValueOf(NewErrorResponse(fmt.Errorf("missing message count parameter")))
	}

	messageCount := args[0].Int()
	if messageCount <= 0 || messageCount > MaxMessagesPerCredential {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("message count must be between 1 and %d", MaxMessagesPerCredential),
		))
	}

	// Generate key pair
	keyPair, err := core.GenerateKeyPair(messageCount, nil)
	if err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	// Serialize public key
	publicKeyBytes, err := serializePublicKey(keyPair.PublicKey)
	if err != nil {
		return js.ValueOf(map[string]interface{}{
			"error":   true,
			"message": fmt.Sprintf("Failed to serialize public key: %v", err),
		})
	}
	
	// Serialize private key (just the scalar value)
	privateKeyBytes := keyPair.PrivateKey.Value.Bytes()

	// Encode to Base64
	publicKeyB64 := encodeToBase64(publicKeyBytes)
	privateKeyB64 := encodeToBase64(privateKeyBytes)

	// Create response
	response := KeyPairResponse{
		PrivateKey:   privateKeyB64,
		PublicKey:    publicKeyB64,
		MessageCount: messageCount,
	}

	// Convert to JS object
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	// Parse JSON into JS object
	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	return js.ValueOf(result)
}

// Sign creates a signature on messages
func Sign(this js.Value, args []js.Value) interface{} {
	// Validate input
	if len(args) < 3 {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("missing parameters: privateKey, publicKey, messages"),
		))
	}

	// Get private key
	privateKeyB64 := args[0].String()
	privateKeyBytes, err := decodeFromBase64(privateKeyB64)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid private key encoding: %v", err),
		))
	}
	privateKey := &core.PrivateKey{
		Value: new(big.Int).SetBytes(privateKeyBytes),
	}

	// Get public key
	publicKeyB64 := args[1].String()
	publicKeyBytes, err := decodeFromBase64(publicKeyB64)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid public key encoding: %v", err),
		))
	}
	publicKey, err := deserializePublicKey(publicKeyBytes)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid public key format: %v", err),
		))
	}

	// Get messages
	messagesObj := args[2]
	if !messagesObj.IsObject() {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("messages must be an object"),
		))
	}

	// Check if messages is an array or has a "messages" property
	var messagesArr js.Value
	if messagesObj.Get("messages").IsArray() {
		messagesArr = messagesObj.Get("messages")
	} else if messagesObj.IsArray() {
		messagesArr = messagesObj
	} else {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("messages must be an array or an object with a 'messages' array property"),
		))
	}

	// Convert JS messages to Go
	messageCount := messagesArr.Length()
	if messageCount != publicKey.MessageCount {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("message count mismatch: expected %d, got %d", publicKey.MessageCount, messageCount),
		))
	}

	messages := make([]*big.Int, messageCount)
	for i := 0; i < messageCount; i++ {
		msgStr := messagesArr.Index(i).String()
		// Hash the message to get a value in the field
		messages[i] = hashToField(msgStr)
	}

	// Get optional header
	var header []byte
	if len(args) > 3 && !args[3].IsUndefined() && !args[3].IsNull() {
		headerStr := args[3].String()
		header = []byte(headerStr)
	}

	// Sign the messages
	signature, err := core.Sign(privateKey, publicKey, messages, header)
	if err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	// Serialize the signature
	signatureBytes, err := serializeSignature(signature)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("failed to serialize signature: %v", err),
		))
	}

	// Encode to Base64
	signatureB64 := encodeToBase64(signatureBytes)

	// Create response
	response := SignatureResponse{
		Signature: signatureB64,
	}

	// Convert to JS object
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	// Parse JSON into JS object
	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	return js.ValueOf(result)
}

// Verify checks a signature
func Verify(this js.Value, args []js.Value) interface{} {
	// Validate input
	if len(args) < 3 {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("missing parameters: publicKey, signature, messages"),
		))
	}

	// Get public key
	publicKeyB64 := args[0].String()
	publicKeyBytes, err := decodeFromBase64(publicKeyB64)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid public key encoding: %v", err),
		))
	}
	publicKey, err := deserializePublicKey(publicKeyBytes)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid public key format: %v", err),
		))
	}

	// Get signature
	signatureB64 := args[1].String()
	signatureBytes, err := decodeFromBase64(signatureB64)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid signature encoding: %v", err),
		))
	}
	signature, err := deserializeSignature(signatureBytes)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid signature format: %v", err),
		))
	}

	// Get messages
	messagesObj := args[2]
	if !messagesObj.IsObject() {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("messages must be an object"),
		))
	}

	// Check if messages is an array or has a "messages" property
	var messagesArr js.Value
	if messagesObj.Get("messages").IsArray() {
		messagesArr = messagesObj.Get("messages")
	} else if messagesObj.IsArray() {
		messagesArr = messagesObj
	} else {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("messages must be an array or an object with a 'messages' array property"),
		))
	}

	// Convert JS messages to Go
	messageCount := messagesArr.Length()
	if messageCount != publicKey.MessageCount {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("message count mismatch: expected %d, got %d", publicKey.MessageCount, messageCount),
		))
	}

	messages := make([]*big.Int, messageCount)
	for i := 0; i < messageCount; i++ {
		msgStr := messagesArr.Index(i).String()
		// Hash the message to get a value in the field
		messages[i] = hashToField(msgStr)
	}

	// Get optional header
	var header []byte
	if len(args) > 3 && !args[3].IsUndefined() && !args[3].IsNull() {
		headerStr := args[3].String()
		header = []byte(headerStr)
	}

	// Verify the signature
	err = core.Verify(publicKey, signature, messages, header)
	if err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	// Return success
	return js.ValueOf(map[string]interface{}{
		"error":   false,
		"valid":   true,
		"message": "Signature is valid",
	})
}

// CreateProof creates a selective disclosure proof
func CreateProof(this js.Value, args []js.Value) interface{} {
	// Validate input
	if len(args) < 1 || !args[0].IsObject() {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("missing or invalid parameters object"),
		))
	}

	params := args[0]

	// Get public key
	publicKeyB64 := params.Get("publicKey").String()
	publicKeyBytes, err := decodeFromBase64(publicKeyB64)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid public key encoding: %v", err),
		))
	}
	publicKey, err := deserializePublicKey(publicKeyBytes)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid public key format: %v", err),
		))
	}

	// Get signature
	signatureB64 := params.Get("signature").String()
	signatureBytes, err := decodeFromBase64(signatureB64)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid signature encoding: %v", err),
		))
	}
	signature, err := deserializeSignature(signatureBytes)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid signature format: %v", err),
		))
	}

	// Get messages
	messagesArr := params.Get("messages")
	if !messagesArr.IsArray() {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("messages must be an array"),
		))
	}

	// Convert JS messages to Go
	messageCount := messagesArr.Length()
	if messageCount != publicKey.MessageCount {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("message count mismatch: expected %d, got %d", publicKey.MessageCount, messageCount),
		))
	}

	messages := make([]*big.Int, messageCount)
	for i := 0; i < messageCount; i++ {
		msgStr := messagesArr.Index(i).String()
		// Hash the message to get a value in the field
		messages[i] = hashToField(msgStr)
	}

	// Get disclosed indices
	disclosedIndicesArr := params.Get("disclosedIndices")
	if !disclosedIndicesArr.IsArray() {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("disclosedIndices must be an array"),
		))
	}

	disclosedIndices := make([]int, disclosedIndicesArr.Length())
	for i := 0; i < disclosedIndicesArr.Length(); i++ {
		disclosedIndices[i] = disclosedIndicesArr.Index(i).Int()
		if disclosedIndices[i] < 0 || disclosedIndices[i] >= messageCount {
			return js.ValueOf(NewErrorResponse(
				fmt.Errorf("invalid disclosed index: %d", disclosedIndices[i]),
			))
		}
	}

	// Get optional header
	var header []byte
	headerVal := params.Get("header")
	if !headerVal.IsUndefined() && !headerVal.IsNull() {
		headerStr := headerVal.String()
		header = []byte(headerStr)
	}

	// Create the proof using the builder for more flexibility
	proofBuilder := proof.NewBuilder()
	proofBuilder.SetPublicKey(publicKey)
	proofBuilder.SetSignature(signature)
	proofBuilder.SetMessages(messages)
	proofBuilder.SetHeader(header)
	
	// Check for predicates
	predicatesVal := params.Get("predicates")
	if !predicatesVal.IsUndefined() && !predicatesVal.IsNull() && predicatesVal.IsArray() {
		for i := 0; i < predicatesVal.Length(); i++ {
			predObj := predicatesVal.Index(i)
			if !predObj.IsObject() {
				continue
			}
			
			// Get predicate details
			idxVal := predObj.Get("index")
			typeVal := predObj.Get("type")
			valueVal := predObj.Get("value")
			
			if idxVal.IsNumber() && typeVal.IsString() && !valueVal.IsUndefined() {
				idx := idxVal.Int()
				typ := typeVal.String()
				
				var predType proof.PredicateType
				switch typ {
				case "eq", "equals":
					predType = proof.PredicateEquals
				case "gt", "greaterThan":
					predType = proof.PredicateGreaterThan
				case "lt", "lessThan":
					predType = proof.PredicateLessThan
				case "ne", "notEqual":
					predType = proof.PredicateNotEqual
				case "range", "inRange":
					predType = proof.PredicateInRange
				default:
					continue // Skip unknown predicate types
				}
				
				// Process value based on predicate type
				if predType == proof.PredicateInRange {
					// For range predicates, value should be an array of [min, max]
					if !valueVal.IsArray() || valueVal.Length() != 2 {
						continue
					}
					
					minVal := valueVal.Index(0)
					maxVal := valueVal.Index(1)
					if !minVal.IsNumber() || !maxVal.IsNumber() {
						continue
					}
					
					minBig := hashToField(minVal.String())
					maxBig := hashToField(maxVal.String())
					
					proofBuilder.AddPredicate(idx, predType, minBig, maxBig)
				} else {
					// For single value predicates
					valBig := hashToField(valueVal.String())
					proofBuilder.AddPredicate(idx, predType, valBig)
				}
			}
		}
	}
	
	// Add disclosed indices
	for _, idx := range disclosedIndices {
		proofBuilder.Disclose(idx)
	}
	
	// Build the proof
	p, disclosed, err := proofBuilder.Build()
	if err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	// Serialize the proof using the serializer
	serializer := proof.NewProofSerializer()
	
	// Serialize the proof to Base64
	proofB64, err := serializer.ProofToBase64(p)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("failed to serialize proof: %v", err),
		))
	}
	
	// Serialize the disclosed messages to Base64
	disclosedB64, err := serializer.DisclosedMessagesToBase64(disclosed)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("failed to serialize disclosed messages: %v", err),
		))
	}
	
	// Convert disclosed messages to string map for JS
	disclosedStrMap := make(map[string]string)
	for idx, val := range disclosed {
		// Convert indices to strings for JSON keys
		disclosedStrMap[fmt.Sprintf("%d", idx)] = messagesArr.Index(idx).String()
	}

	// Create response
	response := ProofResponse{
		Proof:             proofB64,
		DisclosedMessages: disclosedStrMap,
	}

	// Convert to JS object
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	// Parse JSON into JS object
	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	return js.ValueOf(result)
}

// VerifyProof checks a selective disclosure proof
func VerifyProof(this js.Value, args []js.Value) interface{} {
	// Validate input
	if len(args) < 1 || !args[0].IsObject() {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("missing or invalid parameters object"),
		))
	}

	params := args[0]

	// Get public key
	publicKeyB64 := params.Get("publicKey").String()
	publicKeyBytes, err := decodeFromBase64(publicKeyB64)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid public key encoding: %v", err),
		))
	}
	publicKey, err := deserializePublicKey(publicKeyBytes)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("invalid public key format: %v", err),
		))
	}

	// Get proof
	proofB64 := params.Get("proof").String()
	
	// Get disclosed messages
	disclosedB64 := params.Get("disclosedMessages").String()
	
	// Deserialize the proof and disclosed messages using the serializer
	serializer := proof.NewProofSerializer()
	
	// Deserialize the proof from Base64
	p, err := serializer.ProofFromBase64(proofB64)
	if err != nil {
		return js.ValueOf(NewErrorResponse(
			fmt.Errorf("failed to deserialize proof: %v", err),
		))
	}
	
	// Deserialize the disclosed messages from Base64
	disclosed, err := serializer.DisclosedMessagesFromBase64(disclosedB64)
	if err != nil {
		// If the disclosed messages are not in the serialized format,
		// try to parse them from the JS object
		disclosed = make(map[int]*big.Int)
		
		disclosedObj := params.Get("disclosedMessages")
		if disclosedObj.IsObject() {
			// Get all keys in the object
			var keys []string
			keysVal := js.Global().Get("Object").Call("keys", disclosedObj)
			for i := 0; i < keysVal.Length(); i++ {
				keys = append(keys, keysVal.Index(i).String())
			}
			
			// Process each key-value pair
			for _, key := range keys {
				// Parse the key as an index
				var idx int
				if _, err := fmt.Sscanf(key, "%d", &idx); err != nil {
					continue
				}
				
				// Get the value
				val := disclosedObj.Get(key).String()
				
				// Convert to big.Int
				disclosed[idx] = hashToField(val)
			}
		}
	}

	// Get optional header
	var header []byte
	headerVal := params.Get("header")
	if !headerVal.IsUndefined() && !headerVal.IsNull() {
		headerStr := headerVal.String()
		header = []byte(headerStr)
	}

	// Verify the proof using the verifier
	verifier := proof.NewVerifier()
	verifier.SetPublicKey(publicKey)
	verifier.SetProof(p)
	verifier.SetDisclosedMessages(disclosed)
	verifier.SetHeader(header)
	
	err = verifier.Verify()
	if err != nil {
		return js.ValueOf(NewErrorResponse(err))
	}

	// Return success
	return js.ValueOf(map[string]interface{}{
		"error":   false,
		"valid":   true,
		"message": "Proof is valid",
	})
}

// Helper functions

// serializePublicKey serializes a public key to bytes
func serializePublicKey(pk *core.PublicKey) ([]byte, error) {
	// For simplicity, we'll use JSON for serialization
	// In a production system, you might want a more efficient binary serialization
	type SerializedPK struct {
		W            []byte   `json:"w"`
		H            [][]byte `json:"h"`
		H0           []byte   `json:"h0"`
		G1           []byte   `json:"g1"`
		G2           []byte   `json:"g2"`
		MessageCount int      `json:"messageCount"`
	}

	// Marshal W
	wBytes := pk.W.Marshal()

	// Marshal H array
	hBytes := make([][]byte, len(pk.H))
	for i, h := range pk.H {
		hBytes[i] = h.Marshal()
	}

	// Marshal H0
	h0Bytes := pk.H0.Marshal()

	// Marshal G1 and G2
	g1Bytes := pk.G1.Marshal()
	g2Bytes := pk.G2.Marshal()

	// Create serialized struct
	serialized := SerializedPK{
		W:            wBytes,
		H:            hBytes,
		H0:           h0Bytes,
		G1:           g1Bytes,
		G2:           g2Bytes,
		MessageCount: pk.MessageCount,
	}

	// Convert to JSON
	return json.Marshal(serialized)
}

// deserializePublicKey deserializes a public key from bytes
func deserializePublicKey(data []byte) (*core.PublicKey, error) {
	// Parse JSON
	type SerializedPK struct {
		W            []byte   `json:"w"`
		H            [][]byte `json:"h"`
		H0           []byte   `json:"h0"`
		G1           []byte   `json:"g1"`
		G2           []byte   `json:"g2"`
		MessageCount int      `json:"messageCount"`
	}

	var serialized SerializedPK
	if err := json.Unmarshal(data, &serialized); err != nil {
		return nil, err
	}

	// Create public key
	pk := &core.PublicKey{
		MessageCount: serialized.MessageCount,
	}

	// Unmarshal W
	if err := pk.W.Unmarshal(serialized.W); err != nil {
		return nil, fmt.Errorf("failed to unmarshal W: %v", err)
	}

	// Unmarshal H array
	pk.H = make([]bls12381.G1Affine, len(serialized.H))
	for i, hBytes := range serialized.H {
		if err := pk.H[i].Unmarshal(hBytes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal H[%d]: %v", i, err)
		}
	}

	// Unmarshal H0
	if err := pk.H0.Unmarshal(serialized.H0); err != nil {
		return nil, fmt.Errorf("failed to unmarshal H0: %v", err)
	}

	// Unmarshal G1
	if err := pk.G1.Unmarshal(serialized.G1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal G1: %v", err)
	}

	// Unmarshal G2
	if err := pk.G2.Unmarshal(serialized.G2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal G2: %v", err)
	}

	return pk, nil
}

// serializeSignature serializes a signature to bytes
func serializeSignature(sig *core.Signature) ([]byte, error) {
	// For simplicity, we'll use JSON for serialization
	// In a production system, you might want a more efficient binary serialization
	type SerializedSig struct {
		A []byte `json:"a"`
		E []byte `json:"e"`
		S []byte `json:"s"`
	}

	// Marshal A
	aBytes := sig.A.Marshal()

	// Marshal E and S
	eBytes := sig.E.Bytes()
	sBytes := sig.S.Bytes()

	// Create serialized struct
	serialized := SerializedSig{
		A: aBytes,
		E: eBytes,
		S: sBytes,
	}

	// Convert to JSON
	return json.Marshal(serialized)
}

// deserializeSignature deserializes a signature from bytes
func deserializeSignature(data []byte) (*core.Signature, error) {
	// Parse JSON
	type SerializedSig struct {
		A []byte `json:"a"`
		E []byte `json:"e"`
		S []byte `json:"s"`
	}

	var serialized SerializedSig
	if err := json.Unmarshal(data, &serialized); err != nil {
		return nil, err
	}

	// Create signature
	sig := &core.Signature{
		E: new(big.Int).SetBytes(serialized.E),
		S: new(big.Int).SetBytes(serialized.S),
	}

	// Unmarshal A
	if err := sig.A.Unmarshal(serialized.A); err != nil {
		return nil, fmt.Errorf("failed to unmarshal A: %v", err)
	}

	return sig, nil
}

// hashToField hashes a string to a field element
func hashToField(msg string) *big.Int {
	// Use the bls12-381 hash function
	h := bls12381.NewHash()
	h.Write([]byte(msg))
	hashBytes := h.Sum(nil)
	
	// Convert to big.Int and mod by the field order
	return new(big.Int).Mod(new(big.Int).SetBytes(hashBytes), bls12381.Order)
}

// encodeToBase64 encodes bytes to base64
func encodeToBase64(data []byte) string {
	return bls12381.EncodeToBase64(data)
}

// decodeFromBase64 decodes base64 to bytes
func decodeFromBase64(b64 string) ([]byte, error) {
	return bls12381.DecodeFromBase64(b64)
}