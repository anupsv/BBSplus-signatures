package bbs

import (
	"crypto/rand"
	"math/big"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// SignatureManager provides optimized memory management for signature operations
// It uses object pooling to reduce memory allocations and improve performance
type SignatureManager struct {
	// Use a RWMutex to allow concurrent read operations
	mu sync.RWMutex
	
	// Pool for frequently used temporary values
	tempPool *ObjectPool
	
	// Cache signing-specific calculations
	domainCache sync.Map // map[string]*big.Int
	
	// Maximum entries in cache before cleanup
	maxCacheSize int
}

// NewSignatureManager creates a new signature manager with optimized memory usage
// If objectPool is nil, it will use the default global pool
func NewSignatureManager(objectPool *ObjectPool, maxCacheSize int) *SignatureManager {
	if objectPool == nil {
		objectPool = defaultPool
	}
	
	if maxCacheSize <= 0 {
		maxCacheSize = 100 // Default cache size
	}
	
	return &SignatureManager{
		tempPool:     objectPool,
		maxCacheSize: maxCacheSize,
	}
}

// Default singleton manager
var defaultManager = NewSignatureManager(nil, 0)

// SignWithPooling creates a BBS+ signature with optimized memory usage
// It uses object pooling for intermediate values
func (sm *SignatureManager) SignWithPooling(
	sk *PrivateKey,
	pk *PublicKey,
	messages []*big.Int,
	header []byte,
) (*Signature, error) {
	// Validate inputs
	if len(messages) != pk.MessageCount {
		return nil, ErrInvalidMessageCount
	}
	
	// Calculate domain value (using cache if possible)
	domain := sm.getDomainCached(pk, header)
	
	// Generate random values e, s from Zp using constant-time implementation
	e, err := ConstantTimeRandom(rand.Reader, Order)
	if err != nil {
		return nil, err
	}
	
	s, err := ConstantTimeRandom(rand.Reader, Order)
	if err != nil {
		return nil, err
	}
	
	// Use pooled resources for signature computation
	// Get a Jacobian point from the pool for B
	BJac := sm.tempPool.GetG1Jac()
	defer sm.tempPool.PutG1Jac(BJac)
	
	// Start with g1 (P1)
	BJac.FromAffine(&pk.G1)

	// Add Q1 * s (using pooled point)
	q1sJac := sm.tempPool.GetG1Jac()
	defer sm.tempPool.PutG1Jac(q1sJac)
	
	q1sJac.FromAffine(&pk.H[0])
	q1sJac.ScalarMultiplication(q1sJac, s)
	BJac.AddAssign(q1sJac)
	
	// Add Q2 * domain (using pooled point)
	q2domJac := sm.tempPool.GetG1Jac()
	defer sm.tempPool.PutG1Jac(q2domJac)
	
	q2domJac.FromAffine(&pk.H[1])
	q2domJac.ScalarMultiplication(q2domJac, domain)
	BJac.AddAssign(q2domJac)
	
	// Add each H_i * m_i (using a pooled point that gets reused)
	hiJac := sm.tempPool.GetG1Jac()
	defer sm.tempPool.PutG1Jac(hiJac)
	
	for i, m := range messages {
		hiJac.FromAffine(&pk.H[i+2]) // +2 because H[0] is Q1, H[1] is Q2
		hiJac.ScalarMultiplication(hiJac, m)
		BJac.AddAssign(hiJac)
	}
	
	// Convert to affine
	B := g1JacToAffine(*BJac)
	
	// Compute A = B^(1/(x+e))
	// First, compute 1/(x+e) using constant time operations
	xPlusE := sm.tempPool.GetBigInt()
	defer sm.tempPool.PutBigInt(xPlusE)
	
	xPlusE.Add(sk.X, e)
	
	// Use constant-time modular inverse
	inv := ConstantTimeModInverse(xPlusE, Order)
	
	// Then, compute A = B^(1/(x+e))
	AJac := sm.tempPool.GetG1Jac()
	defer sm.tempPool.PutG1Jac(AJac)
	
	AJac.FromAffine(&B)
	AJac.ScalarMultiplication(AJac, inv)
	
	// Convert to affine
	A := g1JacToAffine(*AJac)
	
	return &Signature{
		A: A,
		E: e,
		S: s,
	}, nil
}

// VerifyWithPooling verifies a signature with optimized memory usage
func (sm *SignatureManager) VerifyWithPooling(
	pk *PublicKey,
	signature *Signature,
	messages []*big.Int,
	header []byte,
) error {
	// Validate inputs
	if len(messages) != pk.MessageCount {
		return ErrInvalidMessageCount
	}
	
	// Calculate domain value (using cache)
	domain := sm.getDomainCached(pk, header)
	
	// Use object pooling for verification
	// Get points from pool
	BJac := sm.tempPool.GetG1Jac()
	defer sm.tempPool.PutG1Jac(BJac)
	
	// Start with g1 (P1)
	BJac.FromAffine(&pk.G1)
	
	// Use a single pooled Jacobian point for all calculations
	tempJac := sm.tempPool.GetG1Jac() 
	defer sm.tempPool.PutG1Jac(tempJac)
	
	// Add Q1 * s
	tempJac.FromAffine(&pk.H[0])
	tempJac.ScalarMultiplication(tempJac, signature.S)
	BJac.AddAssign(tempJac)
	
	// Add Q2 * domain
	tempJac.FromAffine(&pk.H[1])
	tempJac.ScalarMultiplication(tempJac, domain)
	BJac.AddAssign(tempJac)
	
	// Add each H_i * m_i
	for i, m := range messages {
		tempJac.FromAffine(&pk.H[i+2]) // +2 because H[0] is Q1, H[1] is Q2
		tempJac.ScalarMultiplication(tempJac, m)
		BJac.AddAssign(tempJac)
	}
	
	// Convert to affine
	B := g1JacToAffine(*BJac)
	
	// Compute w * g2^e = W + P2 * e
	// Get G2 Jacobian point from pool
	wg2eJac := sm.tempPool.GetG2Jac()
	defer sm.tempPool.PutG2Jac(wg2eJac)
	
	// Start with w (same as W)
	wg2eJac.FromAffine(&pk.W)
	
	// Get another G2 Jacobian point for g2^e
	g2eJac := sm.tempPool.GetG2Jac()
	defer sm.tempPool.PutG2Jac(g2eJac)
	
	// Add g2^e (P2 * e)
	g2eJac.FromAffine(&pk.G2)
	g2eJac.ScalarMultiplication(g2eJac, signature.E)
	wg2eJac.AddAssign(g2eJac)
	
	// Convert to affine
	wg2e := g2JacToAffine(*wg2eJac)
	
	// Negate g2 for the second pairing
	negG2Jac := *sm.tempPool.GetG2Jac()
	defer sm.tempPool.PutG2Jac(&negG2Jac)
	
	negG2Jac.FromAffine(&pk.G2)
	negG2Jac.Neg(&negG2Jac)
	negG2 := g2JacToAffine(negG2Jac)
	
	// Use pooled slices for pairing computation
	g1Points := sm.tempPool.GetG1AffineSlice(2)
	defer sm.tempPool.PutG1AffineSlice(g1Points)
	
	g1Points = append(g1Points, signature.A, B)
	
	g2Points := sm.tempPool.GetG2AffineSlice(2)
	defer sm.tempPool.PutG2AffineSlice(g2Points)
	
	g2Points = append(g2Points, wg2e, negG2)
	
	// Check e(A, W + P2*e) * e(B, -P2) = 1
	// This is equivalent to e(A, W + P2*e) = e(B, P2)
	pairingResult, err := bls12381.Pair(g1Points, g2Points)
	if err != nil {
		return ErrPairingFailed
	}
	
	// Check if the pairing result is 1
	if !pairingResult.IsOne() {
		return ErrInvalidSignature
	}
	
	return nil
}

// BatchVerifySignatures verifies multiple signatures in batch with optimized memory usage
func (sm *SignatureManager) BatchVerifySignatures(
	publicKeys []*PublicKey,
	signatures []*Signature,
	messagesList [][]*big.Int,
	headers [][]byte,
) error {
	// Validate inputs
	if len(publicKeys) != len(signatures) || len(signatures) != len(messagesList) {
		return ErrInvalidArrayLengths
	}
	
	if len(headers) != 0 && len(headers) != len(signatures) {
		return ErrInvalidArrayLengths
	}
	
	// If only one signature, use regular verification
	if len(signatures) == 1 {
		return sm.VerifyWithPooling(publicKeys[0], signatures[0], messagesList[0], headers[0])
	}
	
	// Generate random scalars for batch verification using constant-time operations
	batchScalars := sm.tempPool.GetScalarSlice(len(signatures))
	defer sm.tempPool.PutScalarSlice(batchScalars)
	
	// Generate cryptographically strong random scalars
	for i := range batchScalars {
		var err error
		batchScalars[i], err = ConstantTimeRandom(rand.Reader, Order)
		if err != nil {
			return err
		}
	}
	
	// Pre-allocate the arrays with the expected capacity
	pointCapacity := len(signatures) * 2 // Each signature contributes 2 points
	
	g1Points := sm.tempPool.GetG1AffineSlice(pointCapacity)
	defer sm.tempPool.PutG1AffineSlice(g1Points)
	
	g2Points := sm.tempPool.GetG2AffineSlice(pointCapacity)
	defer sm.tempPool.PutG2AffineSlice(g2Points)
	
	// Process each signature using memory pooling
	for i, signature := range signatures {
		publicKey := publicKeys[i]
		messages := messagesList[i]
		
		// Get domain value (using cache)
		var domain *big.Int
		if i < len(headers) && headers[i] != nil {
			domain = sm.getDomainCached(publicKey, headers[i])
		} else {
			domain = sm.getDomainCached(publicKey, nil)
		}
		
		// Multiply by batch scalar for this signature
		batchScalar := batchScalars[i]
		
		// Compute B (reuse calculations from individual verification)
		BJac := sm.tempPool.GetG1Jac()
		tempJac := sm.tempPool.GetG1Jac()
		
		// Start with g1 (P1)
		BJac.FromAffine(&publicKey.G1)
		
		// Add Q1 * s
		tempJac.FromAffine(&publicKey.H[0])
		tempJac.ScalarMultiplication(tempJac, signature.S)
		BJac.AddAssign(tempJac)
		
		// Add Q2 * domain
		tempJac.FromAffine(&publicKey.H[1])
		tempJac.ScalarMultiplication(tempJac, domain)
		BJac.AddAssign(tempJac)
		
		// Add each H_i * m_i
		for j, m := range messages {
			tempJac.FromAffine(&publicKey.H[j+2]) // +2 because H[0] is Q1, H[1] is Q2
			tempJac.ScalarMultiplication(tempJac, m)
			BJac.AddAssign(tempJac)
		}
		
		// Scale by batch scalar
		BJac.ScalarMultiplication(BJac, batchScalar)
		
		// Convert to affine
		B := g1JacToAffine(*BJac)
		
		// Compute w * g2^e = W + P2 * e
		wg2eJac := sm.tempPool.GetG2Jac()
		g2eJac := sm.tempPool.GetG2Jac()
		
		// Start with w (same as W)
		wg2eJac.FromAffine(&publicKey.W)
		
		// Add g2^e (P2 * e)
		g2eJac.FromAffine(&publicKey.G2)
		g2eJac.ScalarMultiplication(g2eJac, signature.E)
		wg2eJac.AddAssign(g2eJac)
		
		// Scale by batch scalar
		wg2eJac.ScalarMultiplication(wg2eJac, batchScalar)
		
		// Convert to affine
		wg2e := g2JacToAffine(*wg2eJac)
		
		// Release temporary pooled resources
		sm.tempPool.PutG1Jac(BJac)
		sm.tempPool.PutG1Jac(tempJac)
		sm.tempPool.PutG2Jac(wg2eJac)
		sm.tempPool.PutG2Jac(g2eJac)
		
		// Add points to final pairing check
		g1Points = append(g1Points, signature.A)
		g2Points = append(g2Points, wg2e)
		
		g1Points = append(g1Points, B)
		
		// Negate g2 for the second pairing component
		negG2Jac := sm.tempPool.GetG2Jac()
		negG2Jac.FromAffine(&publicKey.G2)
		negG2Jac.Neg(negG2Jac)
		negG2 := g2JacToAffine(*negG2Jac)
		sm.tempPool.PutG2Jac(negG2Jac)
		
		g2Points = append(g2Points, negG2)
	}
	
	// Perform the batch pairing check
	pairingResult, err := bls12381.Pair(g1Points, g2Points)
	if err != nil {
		return ErrPairingFailed
	}
	
	// Check if the pairing result is 1 (using constant-time comparison)
	if !pairingResult.IsOne() {
		return ErrInvalidSignature
	}
	
	return nil
}

// Domain calculation with caching
func (sm *SignatureManager) getDomainCached(pk *PublicKey, header []byte) *big.Int {
	// Create a cache key
	var key string
	if header != nil {
		key = string(header)
	}
	
	// Add public key fingerprint to the key
	for _, h := range pk.H {
		key += string(h.Marshal()[:8]) // Use first 8 bytes as fingerprint
	}
	
	// Check if we have it in cache
	if cached, ok := sm.domainCache.Load(key); ok {
		return cached.(*big.Int)
	}
	
	// Not in cache, calculate it
	domain := CalculateDomain(pk, header)
	
	// Store in cache
	sm.domainCache.Store(key, domain)
	
	// Check if we need to clean up the cache
	sm.cleanupCacheIfNeeded()
	
	return domain
}

// Cleanup cache if it gets too large
func (sm *SignatureManager) cleanupCacheIfNeeded() {
	var count int
	
	// Count entries (inefficient but sync.Map doesn't provide a direct size method)
	sm.domainCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	
	// If cache is too large, clear it
	if count > sm.maxCacheSize {
		sm.mu.Lock()
		defer sm.mu.Unlock()
		
		// Create a new map
		sm.domainCache = sync.Map{}
	}
}

// Global convenience functions using the default manager

// SignWithPooling creates a signature with optimized memory usage
func SignWithPooling(
	sk *PrivateKey,
	pk *PublicKey,
	messages []*big.Int,
	header []byte,
) (*Signature, error) {
	return defaultManager.SignWithPooling(sk, pk, messages, header)
}

// VerifyWithPooling verifies a signature with optimized memory usage
func VerifyWithPooling(
	pk *PublicKey,
	signature *Signature,
	messages []*big.Int,
	header []byte,
) error {
	return defaultManager.VerifyWithPooling(pk, signature, messages, header)
}

// BatchVerifySignatures verifies multiple signatures in batch
func BatchVerifySignatures(
	publicKeys []*PublicKey,
	signatures []*Signature,
	messagesList [][]*big.Int,
	headers [][]byte,
) error {
	return defaultManager.BatchVerifySignatures(publicKeys, signatures, messagesList, headers)
}