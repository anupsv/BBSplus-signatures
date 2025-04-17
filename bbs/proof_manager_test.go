package bbs

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestProofManager_CreateProofWithPooling(t *testing.T) {
	// Generate test keys
	keyPair, err := GenerateKeyPair(5, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	sk := keyPair.PrivateKey
	pk := keyPair.PublicKey

	// Create messages
	messages := make([]*big.Int, 5)
	for i := 0; i < 5; i++ {
		msg, err := RandomScalar(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}
		messages[i] = msg
	}

	// Sign with standard method
	signature, err := Sign(sk, pk, messages, nil)
	if err != nil {
		t.Fatalf("Standard Sign failed: %v", err)
	}

	// Create proof with pooling
	manager := NewProofManager(nil, 0, 0)
	disclosedIndices := []int{0, 2} // Disclose messages 0 and 2
	_, disclosedMessages, err := manager.CreateProofWithPooling(pk, signature, messages, disclosedIndices, nil)
	if err != nil {
		t.Fatalf("CreateProofWithPooling failed: %v", err)
	}

	// Verify the returned disclosedMessages contains the right messages
	if len(disclosedMessages) != len(disclosedIndices) {
		t.Fatalf("Expected %d disclosed messages, got %d", len(disclosedIndices), len(disclosedMessages))
	}

	for _, idx := range disclosedIndices {
		if disclosedMessages[idx].Cmp(messages[idx]) != 0 {
			t.Fatalf("Disclosed message at index %d doesn't match original", idx)
		}
	}

	// Return the pooled map to avoid memory leaks
	defaultPool.PutDisclosedMsgMap(disclosedMessages)

	// Test global function
	_, disclosedMessages2, err := CreateProofWithPooling(pk, signature, messages, disclosedIndices, nil)
	if err != nil {
		t.Fatalf("Global CreateProofWithPooling failed: %v", err)
	}

	// Return the pooled map to avoid memory leaks
	defaultPool.PutDisclosedMsgMap(disclosedMessages2)

}

func TestProofManager_VerifyProofWithPooling(t *testing.T) {
	// Generate test keys
	keyPair, err := GenerateKeyPair(5, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	sk := keyPair.PrivateKey
	pk := keyPair.PublicKey

	// Create messages
	messages := make([]*big.Int, 5)
	for i := 0; i < 5; i++ {
		msg, err := RandomScalar(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}
		messages[i] = msg
	}

	// Sign with standard method
	signature, err := Sign(sk, pk, messages, nil)
	if err != nil {
		t.Fatalf("Standard Sign failed: %v", err)
	}

	// Create proof with normal method
	disclosedIndices := []int{0, 2} // Disclose messages 0 and 2
	proof, disclosedMessages, err := CreateProof(pk, signature, messages, disclosedIndices, nil)
	if err != nil {
		t.Fatalf("CreateProof failed: %v", err)
	}

	// Verify proof with pooling
	manager := NewProofManager(nil, 0, 0)
	err = manager.VerifyProofWithPooling(pk, proof, disclosedMessages, nil)
	if err != nil {
		t.Fatalf("VerifyProofWithPooling failed: %v", err)
	}

	// Test global function
	err = VerifyProofWithPooling(pk, proof, disclosedMessages, nil)
	if err != nil {
		t.Fatalf("Global VerifyProofWithPooling failed: %v", err)
	}

	// Test invalid proof
	invalidProof := &ProofOfKnowledge{
		APrime: proof.APrime,
		ABar:   proof.ABar,
		D:      proof.D,
		C:      new(big.Int).Add(proof.C, big.NewInt(1)),
		EHat:   proof.EHat,
		SHat:   proof.SHat,
		MHat:   proof.MHat,
	}

	err = manager.VerifyProofWithPooling(pk, invalidProof, disclosedMessages, nil)
	if err == nil {
		t.Fatal("VerifyProofWithPooling should fail with invalid proof")
	}
}

func TestProofManager_ExtendProofWithPooling(t *testing.T) {
	// Generate test keys
	keyPair, err := GenerateKeyPair(5, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	sk := keyPair.PrivateKey
	pk := keyPair.PublicKey

	// Create messages
	messages := make([]*big.Int, 5)
	for i := 0; i < 5; i++ {
		msg, err := RandomScalar(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}
		messages[i] = msg
	}

	// Sign with standard method
	signature, err := Sign(sk, pk, messages, nil)
	if err != nil {
		t.Fatalf("Standard Sign failed: %v", err)
	}

	// Create proof with normal method
	initialDisclosedIndices := []int{0} // Initially disclose only message 0
	proof, disclosedMessages, err := CreateProof(pk, signature, messages, initialDisclosedIndices, nil)
	if err != nil {
		t.Fatalf("CreateProof failed: %v", err)
	}

	// Create a map of all messages for extending the proof
	secretMessages := make(map[int]*big.Int)
	for i, msg := range messages {
		secretMessages[i] = msg
	}

	// Extend the proof with pooling
	manager := NewProofManager(nil, 0, 0)
	additionalIndices := []int{2} // Additionally disclose message 2
	extendedProof, extendedDisclosedMessages, err := manager.ExtendProofWithPooling(
		proof,
		disclosedMessages,
		additionalIndices,
		secretMessages,
		pk,
	)
	if err != nil {
		t.Fatalf("ExtendProofWithPooling failed: %v", err)
	}

	// Verify the extended proof
	err = manager.VerifyProofWithPooling(pk, extendedProof, extendedDisclosedMessages, nil)
	if err != nil {
		t.Fatalf("Verification of extended proof failed: %v", err)
	}

	// Check that additional messages are now disclosed
	if len(extendedDisclosedMessages) != len(initialDisclosedIndices)+len(additionalIndices) {
		t.Fatalf("Extended proof has wrong number of disclosed messages: got %d, expected %d",
			len(extendedDisclosedMessages), len(initialDisclosedIndices)+len(additionalIndices))
	}

	// Check the values of disclosed messages
	for _, idx := range initialDisclosedIndices {
		if extendedDisclosedMessages[idx].Cmp(messages[idx]) != 0 {
			t.Fatalf("Extended proof has wrong value for initial message %d", idx)
		}
	}

	for _, idx := range additionalIndices {
		if extendedDisclosedMessages[idx].Cmp(messages[idx]) != 0 {
			t.Fatalf("Extended proof has wrong value for additional message %d", idx)
		}
	}

	// Return the pooled maps to avoid memory leaks
	defaultPool.PutDisclosedMsgMap(extendedDisclosedMessages)

	// Test global function
	extendedProof2, extendedDisclosedMessages2, err := ExtendProofWithPooling(
		proof,
		disclosedMessages,
		additionalIndices,
		secretMessages,
		pk,
	)
	if err != nil {
		t.Fatalf("Global ExtendProofWithPooling failed: %v", err)
	}

	// Verify the extended proof
	err = VerifyProofWithPooling(pk, extendedProof2, extendedDisclosedMessages2, nil)
	if err != nil {
		t.Fatalf("Verification of extended proof from global function failed: %v", err)
	}

	// Return the pooled map to avoid memory leaks
	defaultPool.PutDisclosedMsgMap(extendedDisclosedMessages2)
}

func TestProofManager_MemoryUsageWithDomainCaching(t *testing.T) {
	// Generate test keys
	keyPair, err := GenerateKeyPair(5, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	sk := keyPair.PrivateKey
	pk := keyPair.PublicKey

	// Create messages
	messages := make([]*big.Int, 5)
	for i := 0; i < 5; i++ {
		msg, err := RandomScalar(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}
		messages[i] = msg
	}

	// Sign with standard method
	signature, err := Sign(sk, pk, messages, nil)
	if err != nil {
		t.Fatalf("Standard Sign failed: %v", err)
	}

	// Create a proof manager with a small cache size to test cleanup
	manager := NewProofManager(nil, 2, 2)
	disclosedIndices := []int{0, 2} // Disclose messages 0 and 2

	// Create multiple proofs to test domain caching
	for i := 0; i < 5; i++ {
		proof, disclosedMessages, err := manager.CreateProofWithPooling(pk, signature, messages, disclosedIndices, nil)
		if err != nil {
			t.Fatalf("CreateProofWithPooling attempt %d failed: %v", i, err)
		}

		// Verify the proof
		err = manager.VerifyProofWithPooling(pk, proof, disclosedMessages, nil)
		if err != nil {
			t.Fatalf("VerifyProofWithPooling attempt %d failed: %v", i, err)
		}

		// Return the pooled map to avoid memory leaks
		defaultPool.PutDisclosedMsgMap(disclosedMessages)
	}

	// The test passes if we reach this point without errors
	// We can't directly verify the cache behavior, but we can ensure
	// that the code handles cache cleanup properly
}
