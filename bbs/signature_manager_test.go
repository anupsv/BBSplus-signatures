package bbs

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestSignatureManager_SignWithPooling(t *testing.T) {
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

	// Test signing with pooling
	manager := NewSignatureManager(nil, 0)
	signature, err := manager.SignWithPooling(sk, pk, messages, nil)
	if err != nil {
		t.Fatalf("SignWithPooling failed: %v", err)
	}

	// Verify signature using standard verification
	err = Verify(pk, signature, messages, nil)
	if err != nil {
		t.Fatalf("Verification of signature created with pooling failed: %v", err)
	}

	// Test global function
	signature2, err := SignWithPooling(sk, pk, messages, nil)
	if err != nil {
		t.Fatalf("Global SignWithPooling failed: %v", err)
	}

	// Verify signature using standard verification
	err = Verify(pk, signature2, messages, nil)
	if err != nil {
		t.Fatalf("Verification of signature created with global function failed: %v", err)
	}
}

func TestSignatureManager_VerifyWithPooling(t *testing.T) {
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

	// Test verification with pooling
	manager := NewSignatureManager(nil, 0)
	err = manager.VerifyWithPooling(pk, signature, messages, nil)
	if err != nil {
		t.Fatalf("VerifyWithPooling failed: %v", err)
	}

	// Test global function
	err = VerifyWithPooling(pk, signature, messages, nil)
	if err != nil {
		t.Fatalf("Global VerifyWithPooling failed: %v", err)
	}

	// Test invalid message count
	invalidMessages := make([]*big.Int, 4)
	copy(invalidMessages, messages)
	err = manager.VerifyWithPooling(pk, signature, invalidMessages, nil)
	if err == nil {
		t.Fatal("VerifyWithPooling should fail with invalid message count")
	}

	// Test invalid signature
	invalidSig := &Signature{
		A: signature.A,
		E: new(big.Int).Add(signature.E, big.NewInt(1)),
		S: signature.S,
	}
	err = manager.VerifyWithPooling(pk, invalidSig, messages, nil)
	if err == nil {
		t.Fatal("VerifyWithPooling should fail with invalid signature")
	}
}

func TestSignatureManager_BatchVerifySignatures(t *testing.T) {
	// Number of signatures to test
	n := 5

	// Generate test keys and signatures
	publicKeys := make([]*PublicKey, n)
	signatures := make([]*Signature, n)
	messagesList := make([][]*big.Int, n)

	for i := 0; i < n; i++ {
		// Generate key pair
		keyPair, err := GenerateKeyPair(3, rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}
		sk := keyPair.PrivateKey
		publicKeys[i] = keyPair.PublicKey

		// Create messages
		messages := make([]*big.Int, 3)
		for j := 0; j < 3; j++ {
			msg, err := RandomScalar(rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate random message: %v", err)
			}
			messages[j] = msg
		}
		messagesList[i] = messages

		// Sign with standard method
		signature, err := Sign(sk, keyPair.PublicKey, messages, nil)
		if err != nil {
			t.Fatalf("Standard Sign failed for signature %d: %v", i, err)
		}
		signatures[i] = signature
	}

	// Test batch verification with pooling
	manager := NewSignatureManager(nil, 0)
	err := manager.BatchVerifySignatures(publicKeys, signatures, messagesList, nil)
	if err != nil {
		t.Fatalf("BatchVerifySignatures failed: %v", err)
	}

	// Test global function
	err = BatchVerifySignatures(publicKeys, signatures, messagesList, nil)
	if err != nil {
		t.Fatalf("Global BatchVerifySignatures failed: %v", err)
	}

	// Test with one invalid signature
	invalidSig := &Signature{
		A: signatures[2].A,
		E: new(big.Int).Add(signatures[2].E, big.NewInt(1)),
		S: signatures[2].S,
	}
	signatures[2] = invalidSig

	err = manager.BatchVerifySignatures(publicKeys, signatures, messagesList, nil)
	if err == nil {
		t.Fatal("BatchVerifySignatures should fail with one invalid signature")
	}

	// Test with mismatched array lengths
	err = manager.BatchVerifySignatures(publicKeys[:n-1], signatures, messagesList, nil)
	if err == nil {
		t.Fatal("BatchVerifySignatures should fail with mismatched array lengths")
	}
}

func TestSignatureManager_DomainCaching(t *testing.T) {
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

	// Test signing and verification with domain caching
	// Create a manager with a small cache size to test cleanup
	manager := NewSignatureManager(nil, 2)

	// Sign multiple times with the same public key
	for i := 0; i < 5; i++ {
		signature, err := manager.SignWithPooling(sk, pk, messages, nil)
		if err != nil {
			t.Fatalf("SignWithPooling attempt %d failed: %v", i, err)
		}

		// Verify the signature
		err = manager.VerifyWithPooling(pk, signature, messages, nil)
		if err != nil {
			t.Fatalf("VerifyWithPooling attempt %d failed: %v", i, err)
		}
	}

	// The test passes if we reach this point without errors
	// We can't directly verify the cache behavior, but we can ensure
	// that the code handles cache cleanup properly
}
