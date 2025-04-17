// Package credential provides functionality for managing BBS+ credentials.
//
// It includes operations for creating, validating, and processing credentials
// based on BBS+ signatures. The package abstracts away the underlying cryptography
// and provides high-level operations for credential management.
//
// Features:
// - Credential creation and issuance
// - Credential serialization and deserialization
// - Credential validation
// - Schema handling and validation
//
// Example usage:
//
//     // Create a credential with attributes
//     credBuilder := credential.NewBuilder()
//     credBuilder.SetSchema("https://example.com/schemas/identity")
//     credBuilder.AddAttribute("name", "John Doe")
//     credBuilder.AddAttribute("age", "30")
//     credBuilder.AddAttribute("email", "john@example.com")
//     
//     // Issue the credential
//     cred, err := credBuilder.Issue(issuerKeyPair)
//     
//     // Serialize to JSON
//     jsonBytes, err := cred.MarshalJSON()
//     
//     // Create a presentation disclosing only name
//     presentation, err := cred.CreatePresentation([]string{"name"})
//
// This package builds on the core BBS+ functionality to provide
// higher-level credential operations.
package credential

// Constants for credential handling
const (
	// DefaultSchemaVersion is the default schema version used for credentials
	DefaultSchemaVersion = "1.0"
	
	// MaxCredentialSize is the maximum size of a credential in bytes
	MaxCredentialSize = 1024 * 1024 // 1MB
	
	// DefaultCredentialContext defines the JSON-LD context for credentials
	DefaultCredentialContext = "https://w3id.org/security/bbs/v1"
)