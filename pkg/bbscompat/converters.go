package bbscompat

import (
	"fmt"
	"math/big"

	"github.com/anupsv/bbsplus-signatures/bbs"
	"github.com/anupsv/bbsplus-signatures/pkg/core"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// KeyConverter converts between old and new key formats
type KeyConverter struct{}

// NewKeyConverter creates a new key converter
func NewKeyConverter() *KeyConverter {
	return &KeyConverter{}
}

// ConvertLegacyPublicKey converts a legacy public key to the new format
func (kc *KeyConverter) ConvertLegacyPublicKey(oldPk *bbs.PublicKey) (*core.PublicKey, error) {
	if oldPk == nil {
		return nil, fmt.Errorf("cannot convert nil public key")
	}

	// Create a new public key
	newPk := &core.PublicKey{
		W:            oldPk.W,
		G1:           oldPk.G1,
		G2:           oldPk.G2,
		MessageCount: oldPk.MessageCount,
	}

	// Copy the H array
	newPk.H = make([]bls12381.G1Affine, len(oldPk.H))
	copy(newPk.H, oldPk.H)

	// Manually set H0 to the first generator (following the convention in the new code)
	if len(oldPk.H) > 0 {
		newPk.H0 = oldPk.H[0]
	} else {
		return nil, fmt.Errorf("legacy public key has no generator points")
	}

	return newPk, nil
}

// ConvertPublicKey converts a new public key to legacy format
func (kc *KeyConverter) ConvertPublicKey(newPk *core.PublicKey) (*bbs.PublicKey, error) {
	if newPk == nil {
		return nil, fmt.Errorf("cannot convert nil public key")
	}

	// Create a legacy public key
	oldPk := &bbs.PublicKey{
		W:            newPk.W,
		G1:           newPk.G1,
		G2:           newPk.G2,
		MessageCount: newPk.MessageCount,
	}

	// Copy the H array
	oldPk.H = make([]bls12381.G1Affine, len(newPk.H))
	copy(oldPk.H, newPk.H)

	return oldPk, nil
}

// ConvertLegacyPrivateKey converts a legacy private key to the new format
func (kc *KeyConverter) ConvertLegacyPrivateKey(oldSk *bbs.PrivateKey) (*core.PrivateKey, error) {
	if oldSk == nil {
		return nil, fmt.Errorf("cannot convert nil private key")
	}

	// Create a new private key
	newSk := &core.PrivateKey{
		Value: new(big.Int).Set(oldSk.X),
	}

	return newSk, nil
}

// ConvertPrivateKey converts a new private key to legacy format
func (kc *KeyConverter) ConvertPrivateKey(newSk *core.PrivateKey) (*bbs.PrivateKey, error) {
	if newSk == nil {
		return nil, fmt.Errorf("cannot convert nil private key")
	}

	// Create a legacy private key
	oldSk := &bbs.PrivateKey{
		X: new(big.Int).Set(newSk.Value),
	}

	return oldSk, nil
}

// ConvertLegacyKeyPair converts a legacy key pair to the new format
func (kc *KeyConverter) ConvertLegacyKeyPair(oldKeyPair *bbs.KeyPair) (*core.KeyPair, error) {
	if oldKeyPair == nil {
		return nil, fmt.Errorf("cannot convert nil key pair")
	}

	// Convert private key
	newSk, err := kc.ConvertLegacyPrivateKey(oldKeyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key: %w", err)
	}

	// Convert public key
	newPk, err := kc.ConvertLegacyPublicKey(oldKeyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}

	// Create a new key pair
	newKeyPair := &core.KeyPair{
		PrivateKey:   newSk,
		PublicKey:    newPk,
		MessageCount: oldKeyPair.PublicKey.MessageCount,
	}

	return newKeyPair, nil
}

// ConvertKeyPair converts a new key pair to legacy format
func (kc *KeyConverter) ConvertKeyPair(newKeyPair *core.KeyPair) (*bbs.KeyPair, error) {
	if newKeyPair == nil {
		return nil, fmt.Errorf("cannot convert nil key pair")
	}

	// Convert private key
	oldSk, err := kc.ConvertPrivateKey(newKeyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key: %w", err)
	}

	// Convert public key
	oldPk, err := kc.ConvertPublicKey(newKeyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}

	// Create a legacy key pair
	oldKeyPair := &bbs.KeyPair{
		PrivateKey: oldSk,
		PublicKey:  oldPk,
	}

	return oldKeyPair, nil
}

// SignatureConverter converts between old and new signature formats
type SignatureConverter struct{}

// NewSignatureConverter creates a new signature converter
func NewSignatureConverter() *SignatureConverter {
	return &SignatureConverter{}
}

// ConvertLegacySignature converts a legacy signature to the new format
func (sc *SignatureConverter) ConvertLegacySignature(oldSig *bbs.Signature) (*core.Signature, error) {
	if oldSig == nil {
		return nil, fmt.Errorf("cannot convert nil signature")
	}

	// Create a new signature
	newSig := &core.Signature{
		A: oldSig.A,
		E: new(big.Int).Set(oldSig.E),
		S: new(big.Int).Set(oldSig.S),
	}

	return newSig, nil
}

// ConvertSignature converts a new signature to legacy format
func (sc *SignatureConverter) ConvertSignature(newSig *core.Signature) (*bbs.Signature, error) {
	if newSig == nil {
		return nil, fmt.Errorf("cannot convert nil signature")
	}

	// Create a legacy signature
	oldSig := &bbs.Signature{
		A: newSig.A,
		E: new(big.Int).Set(newSig.E),
		S: new(big.Int).Set(newSig.S),
	}

	return oldSig, nil
}

// ProofConverter converts between old and new proof formats
type ProofConverter struct{}

// NewProofConverter creates a new proof converter
func NewProofConverter() *ProofConverter {
	return &ProofConverter{}
}

// ConvertLegacyProof converts a legacy proof to the new format
func (pc *ProofConverter) ConvertLegacyProof(oldProof *bbs.ProofOfKnowledge) (*core.ProofOfKnowledge, error) {
	if oldProof == nil {
		return nil, fmt.Errorf("cannot convert nil proof")
	}

	// Create a new proof
	newProof := &core.ProofOfKnowledge{
		APrime: oldProof.APrime,
		ABar:   oldProof.ABar,
		D:      oldProof.D,
		C:      new(big.Int).Set(oldProof.C),
		EHat:   new(big.Int).Set(oldProof.EHat),
		SHat:   new(big.Int).Set(oldProof.SHat),
		MHat:   make([]*big.Int, 0),
		RHat:   make([]*big.Int, 0),
	}

	// Convert the MHat map to a slice
	// This is a simplification - in a real implementation
	// we would need to handle the indices properly
	for _, mhat := range oldProof.MHat {
		newProof.MHat = append(newProof.MHat, new(big.Int).Set(mhat))
	}

	return newProof, nil
}

// ConvertProof converts a new proof to legacy format
func (pc *ProofConverter) ConvertProof(newProof *core.ProofOfKnowledge) (*bbs.ProofOfKnowledge, error) {
	if newProof == nil {
		return nil, fmt.Errorf("cannot convert nil proof")
	}

	// Create a legacy proof
	oldProof := &bbs.ProofOfKnowledge{
		APrime: newProof.APrime,
		ABar:   newProof.ABar,
		D:      newProof.D,
		C:      new(big.Int).Set(newProof.C),
		EHat:   new(big.Int).Set(newProof.EHat),
		SHat:   new(big.Int).Set(newProof.SHat),
		MHat:   make(map[int]*big.Int),
	}

	// Convert the MHat slice to a map
	// This is a simplification - in a real implementation
	// we would need to handle the indices properly
	for i, mhat := range newProof.MHat {
		oldProof.MHat[i] = new(big.Int).Set(mhat)
	}

	return oldProof, nil
}

// ConvertLegacyDisclosedMessages converts a legacy disclosed messages map to the new format
func (pc *ProofConverter) ConvertLegacyDisclosedMessages(oldMessages map[int]*big.Int) map[int]*big.Int {
	if oldMessages == nil {
		return nil
	}

	// Create a new messages map
	newMessages := make(map[int]*big.Int, len(oldMessages))

	// Copy the messages
	for idx, msg := range oldMessages {
		newMessages[idx] = new(big.Int).Set(msg)
	}

	return newMessages
}

// ConvertDisclosedMessages converts a new disclosed messages map to legacy format
// This is the same as ConvertLegacyDisclosedMessages since both use the same format
func (pc *ProofConverter) ConvertDisclosedMessages(newMessages map[int]*big.Int) map[int]*big.Int {
	return pc.ConvertLegacyDisclosedMessages(newMessages)
}

// VerificationHelper provides functions to use new verification code with old data formats
type VerificationHelper struct {
	proofConverter *ProofConverter
	keyConverter   *KeyConverter
}

// NewVerificationHelper creates a new verification helper
func NewVerificationHelper() *VerificationHelper {
	return &VerificationHelper{
		proofConverter: NewProofConverter(),
		keyConverter:   NewKeyConverter(),
	}
}

// VerifyWithNewCode verifies a legacy proof using the new verification code
func (vh *VerificationHelper) VerifyWithNewCode(
	oldPk *bbs.PublicKey,
	oldProof *bbs.ProofOfKnowledge,
	oldMessages map[int]*big.Int,
	header []byte,
) error {
	// Convert old formats to new
	newPk, err := vh.keyConverter.ConvertLegacyPublicKey(oldPk)
	if err != nil {
		return fmt.Errorf("failed to convert public key: %w", err)
	}

	newProof, err := vh.proofConverter.ConvertLegacyProof(oldProof)
	if err != nil {
		return fmt.Errorf("failed to convert proof: %w", err)
	}

	newMessages := vh.proofConverter.ConvertLegacyDisclosedMessages(oldMessages)

	// Use the core package's verification function
	return core.VerifyProof(newPk, newProof, newMessages, header)
}

// LegacyVerifyProof is a compatibility function that uses the same signature as the original
// VerifyProof function but delegates to the core package
func LegacyVerifyProof(
	publicKey *core.PublicKey,
	proof *core.ProofOfKnowledge,
	disclosedMessages map[int]*big.Int,
	header []byte,
) error {
	// Delegate to the core package's verification function
	return core.VerifyProof(publicKey, proof, disclosedMessages, header)
}
