package credential

import (
	"encoding/json"
	"fmt"
	"time"
)

// Presentation represents a selective disclosure presentation of a credential
type Presentation struct {
	// Schema identifies the credential schema
	Schema string `json:"schema"`
	
	// Proof is the BBS+ selective disclosure proof (Base64-encoded)
	Proof string `json:"proof"`
	
	// Attributes contains the disclosed credential attributes
	Attributes map[string]string `json:"attributes"`
	
	// Issuer identifies the original credential issuer
	Issuer string `json:"issuer"`
	
	// Created indicates when the presentation was created
	Created time.Time `json:"created"`
	
	// NonceUsed is the nonce used in the presentation (if any)
	NonceUsed string `json:"nonceUsed,omitempty"`
}

// Verifier provides a fluent interface for verifying presentations
type Verifier struct {
	presentation   *Presentation
	expectedIssuer string
	expectedSchema string
	nonce          string
}

// NewVerifier creates a new presentation verifier
func NewVerifier() *Verifier {
	return &Verifier{}
}

// SetPresentation sets the presentation to verify
func (v *Verifier) SetPresentation(presentation *Presentation) *Verifier {
	v.presentation = presentation
	return v
}

// ExpectIssuer requires the presentation to be from a specific issuer
func (v *Verifier) ExpectIssuer(issuer string) *Verifier {
	v.expectedIssuer = issuer
	return v
}

// ExpectSchema requires the presentation to use a specific schema
func (v *Verifier) ExpectSchema(schema string) *Verifier {
	v.expectedSchema = schema
	return v
}

// SetNonce sets the nonce to verify in the presentation
func (v *Verifier) SetNonce(nonce string) *Verifier {
	v.nonce = nonce
	return v
}

// Verify checks if the presentation is valid
func (v *Verifier) Verify() error {
	if v.presentation == nil {
		return fmt.Errorf("no presentation provided")
	}
	
	// Check issuer if expected
	if v.expectedIssuer != "" && v.presentation.Issuer != v.expectedIssuer {
		return fmt.Errorf("unexpected issuer: expected %s, got %s",
			v.expectedIssuer, v.presentation.Issuer)
	}
	
	// Check schema if expected
	if v.expectedSchema != "" && v.presentation.Schema != v.expectedSchema {
		return fmt.Errorf("unexpected schema: expected %s, got %s",
			v.expectedSchema, v.presentation.Schema)
	}
	
	// Check nonce if provided
	if v.nonce != "" && v.presentation.NonceUsed != v.nonce {
		return fmt.Errorf("incorrect nonce used in presentation")
	}
	
	return fmt.Errorf("BBS+ proof verification not implemented")
}

// MarshalJSON serializes the presentation to JSON
func (p *Presentation) MarshalJSON() ([]byte, error) {
	// Create a copy without private fields
	type presentationExport struct {
		Schema    string            `json:"schema"`
		Proof     string            `json:"proof"`
		Attributes map[string]string `json:"attributes"`
		Issuer    string            `json:"issuer"`
		Created   time.Time         `json:"created"`
		NonceUsed string            `json:"nonceUsed,omitempty"`
	}
	
	export := presentationExport{
		Schema:    p.Schema,
		Proof:     p.Proof,
		Attributes: p.Attributes,
		Issuer:    p.Issuer,
		Created:   p.Created,
		NonceUsed: p.NonceUsed,
	}
	
	return json.Marshal(export)
}

// UnmarshalJSON deserializes a presentation from JSON
func (p *Presentation) UnmarshalJSON(data []byte) error {
	// Create a temporary type to avoid recursion
	type presentationImport struct {
		Schema    string            `json:"schema"`
		Proof     string            `json:"proof"`
		Attributes map[string]string `json:"attributes"`
		Issuer    string            `json:"issuer"`
		Created   time.Time         `json:"created"`
		NonceUsed string            `json:"nonceUsed,omitempty"`
	}
	
	var temp presentationImport
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	
	// Copy imported data
	p.Schema = temp.Schema
	p.Proof = temp.Proof
	p.Attributes = temp.Attributes
	p.Issuer = temp.Issuer
	p.Created = temp.Created
	p.NonceUsed = temp.NonceUsed
	
	return nil
}