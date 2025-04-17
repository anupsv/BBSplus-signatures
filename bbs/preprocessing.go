package bbs

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// MessagePreprocessor handles complex message types and prepares them for signing
// This allows the BBS+ signature scheme to work with structured data formats
type MessagePreprocessor struct {
	// Configuration options
	SortMapKeys          bool // Whether to sort map keys for canonical representation
	IncludeTypeInfo      bool // Whether to include type information in message encoding
	NormalizeWhitespace  bool // Whether to normalize whitespace in string values
	IntegerConversion    string // "native" or "string" depending on how integers should be encoded
	FloatPrecision       int // Number of decimal places to retain for floating point numbers
	EnableMerkleMode     bool // Whether to use Merkle tree mode for large datasets
}

// NewMessagePreprocessor creates a new preprocessor with default settings
func NewMessagePreprocessor() *MessagePreprocessor {
	return &MessagePreprocessor{
		SortMapKeys:         true,
		IncludeTypeInfo:     false, 
		NormalizeWhitespace: true,
		IntegerConversion:   "native",
		FloatPrecision:      6,
		EnableMerkleMode:    false,
	}
}

// PreprocessJSON converts a JSON message into a fieldElement suitable for signing
func (mp *MessagePreprocessor) PreprocessJSON(jsonData []byte) (*big.Int, error) {
	// Parse the JSON into a generic structure
	var data interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	
	// Canonicalize the JSON structure
	canonicalData, err := mp.canonicalizeData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize JSON: %w", err)
	}
	
	// Re-encode to a canonical form
	canonicalJSON, err := json.Marshal(canonicalData)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode JSON: %w", err)
	}
	
	// Hash the canonical form and convert to field element
	return MessageToFieldElement(canonicalJSON), nil
}

// PreprocessXML converts an XML message into a field element suitable for signing
func (mp *MessagePreprocessor) PreprocessXML(xmlData []byte) (*big.Int, error) {
	// Parse the XML into a generic structure
	var data interface{}
	if err := xml.Unmarshal(xmlData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	
	// Normalize XML to a canonical form
	normalized, err := mp.normalizeXML(xmlData)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize XML: %w", err)
	}
	
	// Hash the canonical form and convert to field element
	return MessageToFieldElement(normalized), nil
}

// PreprocessObject converts an arbitrary Go object into a field element
func (mp *MessagePreprocessor) PreprocessObject(obj interface{}) (*big.Int, error) {
	// Convert to JSON first
	jsonData, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to convert object to JSON: %w", err)
	}
	
	// Use JSON preprocessing
	return mp.PreprocessJSON(jsonData)
}

// PreprocessMessageSet converts a set of messages into a Merkle tree and returns the root
func (mp *MessagePreprocessor) PreprocessMessageSet(messages []interface{}) (*big.Int, []*big.Int, error) {
	// Process each message into a field element
	fieldElements := make([]*big.Int, len(messages))
	var err error
	for i, msg := range messages {
		fe, err := mp.PreprocessObject(msg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to preprocess message %d: %w", i, err)
		}
		fieldElements[i] = fe
	}
	
	// Build Merkle tree and get root
	merkleRoot, err := mp.buildMerkleRoot(fieldElements)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build Merkle tree: %w", err)
	}
	
	return merkleRoot, fieldElements, nil
}

// Helper for canonical JSON representation
func (mp *MessagePreprocessor) canonicalizeData(data interface{}) (interface{}, error) {
	switch v := data.(type) {
	case map[string]interface{}:
		// Process map/object
		result := make(map[string]interface{})
		
		// Get keys and optionally sort them
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		
		if mp.SortMapKeys {
			sort.Strings(keys)
		}
		
		// Process each value
		for _, k := range keys {
			canonicalValue, err := mp.canonicalizeData(v[k])
			if err != nil {
				return nil, err
			}
			result[k] = canonicalValue
		}
		
		return result, nil
		
	case []interface{}:
		// Process array
		result := make([]interface{}, len(v))
		for i, item := range v {
			canonicalValue, err := mp.canonicalizeData(item)
			if err != nil {
				return nil, err
			}
			result[i] = canonicalValue
		}
		
		return result, nil
		
	case string:
		// Process string (optionally normalize whitespace)
		if mp.NormalizeWhitespace {
			return normalizeWhitespace(v), nil
		}
		return v, nil
		
	case float64:
		// Process number (with optional precision control)
		if mp.IntegerConversion == "string" && isInteger(v) {
			return fmt.Sprintf("%.0f", v), nil
		}
		
		if mp.FloatPrecision > 0 {
			format := fmt.Sprintf("%%.%df", mp.FloatPrecision)
			return fmt.Sprintf(format, v), nil
		}
		
		return v, nil
		
	case nil, bool:
		// Basic types that don't need processing
		return v, nil
		
	default:
		// Unsupported type
		return nil, fmt.Errorf("unsupported type: %T", v)
	}
}

// normalizeXML creates a canonical form of XML data
func (mp *MessagePreprocessor) normalizeXML(xmlData []byte) ([]byte, error) {
	// In a full implementation, this would implement C14N XML canonicalization
	// https://www.w3.org/TR/xml-c14n/
	
	// For this simplified version, we'll parse and re-marshal with sorted attributes
	var doc interface{}
	if err := xml.Unmarshal(xmlData, &doc); err != nil {
		return nil, err
	}
	
	// Remove all unnecessary whitespace
	var output bytes.Buffer
	encoder := xml.NewEncoder(&output)
	encoder.Indent("", "")
	if err := encoder.Encode(doc); err != nil {
		return nil, err
	}
	
	return output.Bytes(), nil
}

// buildMerkleRoot constructs a Merkle tree from message field elements
func (mp *MessagePreprocessor) buildMerkleRoot(elements []*big.Int) (*big.Int, error) {
	// Special case: empty tree
	if len(elements) == 0 {
		return big.NewInt(0), nil
	}
	
	// Special case: single element
	if len(elements) == 1 {
		return elements[0], nil
	}
	
	// Build bottom level of the tree
	currentLevel := make([]*big.Int, len(elements))
	copy(currentLevel, elements)
	
	// Build tree bottom-up
	for len(currentLevel) > 1 {
		nextLevel := make([]*big.Int, (len(currentLevel)+1)/2)
		
		for i := 0; i < len(nextLevel); i++ {
			// Get left and right children
			leftIdx := i * 2
			rightIdx := i*2 + 1
			
			// If last node and odd number of nodes, duplicate the last node
			if rightIdx >= len(currentLevel) {
				rightIdx = leftIdx
			}
			
			// Hash the pair of nodes
			pair := []byte{}
			pair = append(pair, currentLevel[leftIdx].Bytes()...)
			pair = append(pair, currentLevel[rightIdx].Bytes()...)
			
			hash := sha256.Sum256(pair)
			nextLevel[i] = new(big.Int).SetBytes(hash[:])
		}
		
		currentLevel = nextLevel
	}
	
	// Return the root
	return currentLevel[0], nil
}

// Helper to check if a float represents an integer value
func isInteger(f float64) bool {
	return f == float64(int64(f))
}

// Helper to normalize whitespace in strings
func normalizeWhitespace(s string) string {
	// Replace multiple whitespace characters with a single space
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// MerklePath represents a path in a Merkle tree for proving membership
type MerklePath struct {
	Indices []int          // 0 for left, 1 for right at each level
	Hashes  []*big.Int     // Sibling hashes at each level
}

// GenerateMerkleProof creates a proof that a message is part of a message set
func (mp *MessagePreprocessor) GenerateMerkleProof(messages []interface{}, index int) (*big.Int, *MerklePath, error) {
	if index < 0 || index >= len(messages) {
		return nil, nil, fmt.Errorf("index out of range: %d", index)
	}
	
	// Process each message into a field element
	fieldElements := make([]*big.Int, len(messages))
	for i, msg := range messages {
		fe, err := mp.PreprocessObject(msg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to preprocess message %d: %w", i, err)
		}
		fieldElements[i] = fe
	}
	
	// Build the Merkle tree
	tree := mp.buildMerkleTree(fieldElements)
	
	// Generate the proof
	proof, err := mp.generateProof(tree, index, len(fieldElements))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate proof: %w", err)
	}
	
	// Return the root and the proof
	return tree[0][0], proof, nil
}

// VerifyMerkleProof checks if a message is part of a set with the given Merkle root
func (mp *MessagePreprocessor) VerifyMerkleProof(root *big.Int, element *big.Int, proof *MerklePath) (bool, error) {
	// Start with the element
	current := element
	
	// Traverse the path
	for i := 0; i < len(proof.Indices); i++ {
		// Get the sibling
		sibling := proof.Hashes[i]
		
		// Hash in the correct order
		var combined []byte
		if proof.Indices[i] == 0 {
			// Current is left, sibling is right
			combined = append(combined, current.Bytes()...)
			combined = append(combined, sibling.Bytes()...)
		} else {
			// Current is right, sibling is left
			combined = append(combined, sibling.Bytes()...)
			combined = append(combined, current.Bytes()...)
		}
		
		// Hash the combined value
		hash := sha256.Sum256(combined)
		current = new(big.Int).SetBytes(hash[:])
	}
	
	// Verify that the computed root matches the expected root
	return current.Cmp(root) == 0, nil
}

// buildMerkleTree constructs a full Merkle tree from message field elements
// Returns a 2D array where tree[level][index] is the node at that position
func (mp *MessagePreprocessor) buildMerkleTree(elements []*big.Int) [][]*big.Int {
	// Calculate tree height
	numElements := len(elements)
	height := 0
	for size := numElements; size > 1; size = (size + 1) / 2 {
		height++
	}
	
	// Initialize the tree with the leaf level
	tree := make([][]*big.Int, height+1)
	tree[height] = make([]*big.Int, numElements)
	copy(tree[height], elements)
	
	// Build tree bottom-up
	for level := height; level > 0; level-- {
		numNodes := len(tree[level])
		tree[level-1] = make([]*big.Int, (numNodes+1)/2)
		
		for i := 0; i < len(tree[level-1]); i++ {
			// Get left and right children
			leftIdx := i * 2
			rightIdx := i*2 + 1
			
			// If last node and odd number of nodes, duplicate the last node
			if rightIdx >= numNodes {
				rightIdx = leftIdx
			}
			
			// Hash the pair of nodes
			pair := []byte{}
			pair = append(pair, tree[level][leftIdx].Bytes()...)
			pair = append(pair, tree[level][rightIdx].Bytes()...)
			
			hash := sha256.Sum256(pair)
			tree[level-1][i] = new(big.Int).SetBytes(hash[:])
		}
	}
	
	return tree
}

// generateProof creates a Merkle proof for the element at the given index
func (mp *MessagePreprocessor) generateProof(tree [][]*big.Int, index, numElements int) (*MerklePath, error) {
	proof := &MerklePath{
		Indices: []int{},
		Hashes:  []*big.Int{},
	}
	
	// Start at the leaf level
	currentIndex := index
	
	// For each level (from bottom to top, excluding the root)
	for level := len(tree) - 1; level > 0; level-- {
		// Determine the sibling index
		siblingIndex := -1
		var direction int
		
		if currentIndex%2 == 0 {
			// Current node is left child, sibling is right
			siblingIndex = currentIndex + 1
			direction = 0
		} else {
			// Current node is right child, sibling is left
			siblingIndex = currentIndex - 1
			direction = 1
		}
		
		// Ensure sibling exists
		if siblingIndex < len(tree[level]) {
			proof.Indices = append(proof.Indices, direction)
			proof.Hashes = append(proof.Hashes, tree[level][siblingIndex])
		} else {
			// Handle edge case for odd number of nodes
			proof.Indices = append(proof.Indices, direction)
			proof.Hashes = append(proof.Hashes, tree[level][currentIndex])
		}
		
		// Move to parent
		currentIndex = currentIndex / 2
	}
	
	return proof, nil
}

// StructuredDataSignature creates a signature over structured data
type StructuredDataSignature struct {
	Type          string      // Type of structured data ("json", "xml", "object", "merkle")
	Signature     *Signature  // The actual BBS+ signature
	MerkleRoot    *big.Int    // Merkle root if using a message set
	MerkleIndices []int       // Indices of the signed messages if using a message set
}

// SignStructuredData creates a signature over structured data (JSON, XML, object)
func SignStructuredData(
	sk *PrivateKey,
	pk *PublicKey,
	data interface{}, // Can be raw JSON bytes, XML bytes, or a Go object
	dataType string,  // "json", "xml", "object", or "merkle"
	header []byte,
) (*StructuredDataSignature, error) {
	preprocessor := NewMessagePreprocessor()
	
	// Preprocess based on data type
	var messages []*big.Int
	var merkleRoot *big.Int
	var merkleIndices []int
	
	switch dataType {
	case "json":
		// Convert JSON data to field element
		jsonData, ok := data.([]byte)
		if !ok {
			return nil, fmt.Errorf("data is not JSON bytes")
		}
		
		fe, err := preprocessor.PreprocessJSON(jsonData)
		if err != nil {
			return nil, err
		}
		messages = []*big.Int{fe}
		
	case "xml":
		// Convert XML data to field element
		xmlData, ok := data.([]byte)
		if !ok {
			return nil, fmt.Errorf("data is not XML bytes")
		}
		
		fe, err := preprocessor.PreprocessXML(xmlData)
		if err != nil {
			return nil, err
		}
		messages = []*big.Int{fe}
		
	case "object":
		// Convert object to field element
		fe, err := preprocessor.PreprocessObject(data)
		if err != nil {
			return nil, err
		}
		messages = []*big.Int{fe}
		
	case "merkle":
		// Create a Merkle tree from a set of messages
		messageSet, ok := data.([]interface{})
		if !ok {
			return nil, fmt.Errorf("data is not a message set")
		}
		
		// Build Merkle tree and sign the root
		root, _, err := preprocessor.PreprocessMessageSet(messageSet)
		if err != nil {
			return nil, err
		}
		
		messages = []*big.Int{root}
		merkleRoot = root
		
		// Record all indices for verification
		merkleIndices = make([]int, len(messageSet))
		for i := range messageSet {
			merkleIndices[i] = i
		}
		
	default:
		return nil, fmt.Errorf("unsupported data type: %s", dataType)
	}
	
	// Sign the processed message(s)
	signature, err := Sign(sk, pk, messages, header)
	if err != nil {
		return nil, err
	}
	
	return &StructuredDataSignature{
		Type:          dataType,
		Signature:     signature,
		MerkleRoot:    merkleRoot,
		MerkleIndices: merkleIndices,
	}, nil
}

// VerifyStructuredDataSignature verifies a signature over structured data
func VerifyStructuredDataSignature(
	pk *PublicKey,
	sig *StructuredDataSignature,
	data interface{},
	header []byte,
) (bool, error) {
	preprocessor := NewMessagePreprocessor()
	
	// Preprocess based on data type
	var messages []*big.Int
	
	switch sig.Type {
	case "json":
		// Convert JSON data to field element
		jsonData, ok := data.([]byte)
		if !ok {
			return false, fmt.Errorf("data is not JSON bytes")
		}
		
		fe, err := preprocessor.PreprocessJSON(jsonData)
		if err != nil {
			return false, err
		}
		messages = []*big.Int{fe}
		
	case "xml":
		// Convert XML data to field element
		xmlData, ok := data.([]byte)
		if !ok {
			return false, fmt.Errorf("data is not XML bytes")
		}
		
		fe, err := preprocessor.PreprocessXML(xmlData)
		if err != nil {
			return false, err
		}
		messages = []*big.Int{fe}
		
	case "object":
		// Convert object to field element
		fe, err := preprocessor.PreprocessObject(data)
		if err != nil {
			return false, err
		}
		messages = []*big.Int{fe}
		
	case "merkle":
		// For Merkle trees, we verify against the saved root
		if sig.MerkleRoot == nil {
			return false, fmt.Errorf("missing Merkle root in signature")
		}
		
		// Use the saved Merkle root
		messages = []*big.Int{sig.MerkleRoot}
		
	default:
		return false, fmt.Errorf("unsupported data type: %s", sig.Type)
	}
	
	// Verify the signature
	err := Verify(pk, sig.Signature, messages, header)
	if err != nil {
		return false, err
	}
	
	return true, nil
}

// CreateMerkleProofOfInclusion generates a proof that a specific message is part of a signed Merkle tree
func CreateMerkleProofOfInclusion(
	preprocessor *MessagePreprocessor,
	messages []interface{},
	index int,
	sig *StructuredDataSignature,
) (*MerklePath, error) {
	if sig.Type != "merkle" {
		return nil, fmt.Errorf("signature is not over a Merkle tree")
	}
	
	if index < 0 || index >= len(messages) {
		return nil, fmt.Errorf("index out of range: %d", index)
	}
	
	// Generate the Merkle proof
	_, proof, err := preprocessor.GenerateMerkleProof(messages, index)
	if err != nil {
		return nil, err
	}
	
	return proof, nil
}

// VerifyMerkleProofOfInclusion verifies that a specific message is part of a signed Merkle tree
func VerifyMerkleProofOfInclusion(
	preprocessor *MessagePreprocessor,
	message interface{},
	proof *MerklePath,
	sig *StructuredDataSignature,
) (bool, error) {
	if sig.Type != "merkle" {
		return false, fmt.Errorf("signature is not over a Merkle tree")
	}
	
	if sig.MerkleRoot == nil {
		return false, fmt.Errorf("missing Merkle root in signature")
	}
	
	// Preprocess the message to get its field element
	element, err := preprocessor.PreprocessObject(message)
	if err != nil {
		return false, err
	}
	
	// Verify the Merkle proof
	return preprocessor.VerifyMerkleProof(sig.MerkleRoot, element, proof)
}