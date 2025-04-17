package credential

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/asv/bbs/internal/common"
	"github.com/asv/bbs/pkg/core"
)

// Credential represents a BBS+ credential with attributes
type Credential struct {
	// Schema is the identifier for the credential schema
	Schema string `json:"schema"`
	
	// PublicKey is the issuer's public key (Base64-encoded)
	PublicKey string `json:"publicKey"`
	
	// Signature is the BBS+ signature (Base64-encoded)
	Signature string `json:"signature"`
	
	// Attributes contains the credential attributes
	Attributes map[string]string `json:"attributes"`
	
	// Issuer identifies the credential issuer
	Issuer string `json:"issuer"`
	
	// IssuanceDate is when the credential was issued
	IssuanceDate time.Time `json:"issuanceDate"`
	
	// ExpirationDate is when the credential expires (if applicable)
	ExpirationDate *time.Time `json:"expirationDate,omitempty"`
	
	// proof data for storage
	signature *core.Signature  // Decoded signature
	messages  []*big.Int       // Attribute values as field elements
	attrNames []string         // Ordered attribute names
}

// Builder provides a fluent interface for creating credentials
type Builder struct {
	credential Credential
	keyPair    *core.KeyPair
}

// NewBuilder creates a new credential builder
func NewBuilder() *Builder {
	return &Builder{
		credential: Credential{
			Attributes: make(map[string]string),
			attrNames:  make([]string, 0),
		},
	}
}

// SetSchema sets the credential schema
func (b *Builder) SetSchema(schema string) *Builder {
	b.credential.Schema = schema
	return b
}

// SetIssuer sets the credential issuer
func (b *Builder) SetIssuer(issuer string) *Builder {
	b.credential.Issuer = issuer
	return b
}

// SetExpirationDate sets when the credential expires
func (b *Builder) SetExpirationDate(expiration time.Time) *Builder {
	b.credential.ExpirationDate = &expiration
	return b
}

// AddAttribute adds an attribute to the credential
func (b *Builder) AddAttribute(name, value string) *Builder {
	b.credential.Attributes[name] = value
	b.credential.attrNames = append(b.credential.attrNames, name)
	return b
}

// Issue signs the credential with the issuer's key pair
func (b *Builder) Issue(keyPair *core.KeyPair) (*Credential, error) {
	if keyPair == nil {
		return nil, common.ErrInvalidParameter
	}
	
	// Check if we have the right number of attributes
	if len(b.credential.Attributes) != keyPair.MessageCount {
		return nil, fmt.Errorf("key supports %d attributes, but %d provided",
			keyPair.MessageCount, len(b.credential.Attributes))
	}
	
	// Convert attributes to messages
	messages := make([]*big.Int, len(b.credential.attrNames))
	for i, name := range b.credential.attrNames {
		value := b.credential.Attributes[name]
		msgBytes := []byte(value)
		messages[i] = new(big.Int).SetBytes(msgBytes)
	}
	
	// Sign the messages
	signature, err := core.Sign(keyPair.PrivateKey, keyPair.PublicKey, messages, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}
	
	// Set the signature and key
	b.credential.signature = signature
	b.credential.messages = messages
	b.credential.IssuanceDate = time.Now()
	
	// TODO: Serialize the public key and signature
	
	return &b.credential, nil
}

// Verify checks if the credential is valid
func (c *Credential) Verify() error {
	// Decode the public key and signature
	// TODO: Implement decoding
	
	// Verify the signature
	err := core.Verify(nil, nil, nil, nil) // Use decoded values
	if err != nil {
		return fmt.Errorf("invalid credential: %w", err)
	}
	
	// Check expiration
	if c.ExpirationDate != nil && time.Now().After(*c.ExpirationDate) {
		return fmt.Errorf("credential has expired")
	}
	
	return nil
}

// CreatePresentation creates a selective disclosure presentation
func (c *Credential) CreatePresentation(disclosedAttrs []string) (*Presentation, error) {
	// Find indices of disclosed attributes
	disclosedIndices := make([]int, len(disclosedAttrs))
	for i, attr := range disclosedAttrs {
		found := false
		for j, name := range c.attrNames {
			if name == attr {
				disclosedIndices[i] = j
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("attribute '%s' not found in credential", attr)
		}
	}
	
	// Create the proof
	proof, disclosedMsgs, err := core.CreateProof(nil, c.signature, c.messages, disclosedIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof: %w", err)
	}
	
	// Create a presentation
	presentation := &Presentation{
		Schema:     c.Schema,
		Proof:      nil, // TODO: Serialize proof
		Attributes: make(map[string]string),
		Issuer:     c.Issuer,
		Created:    time.Now(),
	}
	
	// Add disclosed attributes
	for i, idx := range disclosedIndices {
		name := c.attrNames[idx]
		value := c.Attributes[name]
		presentation.Attributes[name] = value
	}
	
	return presentation, nil
}

// MarshalJSON serializes the credential to JSON
func (c *Credential) MarshalJSON() ([]byte, error) {
	// Create a copy without private fields
	type credentialExport struct {
		Schema         string            `json:"schema"`
		PublicKey      string            `json:"publicKey"`
		Signature      string            `json:"signature"`
		Attributes     map[string]string `json:"attributes"`
		Issuer         string            `json:"issuer"`
		IssuanceDate   time.Time         `json:"issuanceDate"`
		ExpirationDate *time.Time        `json:"expirationDate,omitempty"`
	}
	
	export := credentialExport{
		Schema:         c.Schema,
		PublicKey:      c.PublicKey,
		Signature:      c.Signature,
		Attributes:     c.Attributes,
		Issuer:         c.Issuer,
		IssuanceDate:   c.IssuanceDate,
		ExpirationDate: c.ExpirationDate,
	}
	
	return json.Marshal(export)
}

// UnmarshalJSON deserializes a credential from JSON
func (c *Credential) UnmarshalJSON(data []byte) error {
	// Create a temporary type to avoid recursion
	type credentialImport struct {
		Schema         string            `json:"schema"`
		PublicKey      string            `json:"publicKey"`
		Signature      string            `json:"signature"`
		Attributes     map[string]string `json:"attributes"`
		Issuer         string            `json:"issuer"`
		IssuanceDate   time.Time         `json:"issuanceDate"`
		ExpirationDate *time.Time        `json:"expirationDate,omitempty"`
	}
	
	var temp credentialImport
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	
	// Copy imported data
	c.Schema = temp.Schema
	c.PublicKey = temp.PublicKey
	c.Signature = temp.Signature
	c.Attributes = temp.Attributes
	c.Issuer = temp.Issuer
	c.IssuanceDate = temp.IssuanceDate
	c.ExpirationDate = temp.ExpirationDate
	
	// Build attribute names list
	c.attrNames = make([]string, 0, len(c.Attributes))
	for name := range c.Attributes {
		c.attrNames = append(c.attrNames, name)
	}
	
	// TODO: Decode public key and signature
	
	return nil
}