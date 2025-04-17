package bbs

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// ProofManager provides optimized memory management for proof operations
// It uses object pooling to reduce allocations and improve performance
type ProofManager struct {
	// Use a RWMutex to allow concurrent read operations
	mu sync.RWMutex
	
	// Pool for frequently used temporary values
	tempPool *ObjectPool
	
	// Cache proof-specific calculations
	domainCache sync.Map // map[string]*big.Int
	
	// Maximum entries in cache before cleanup
	maxCacheSize int
	
	// Concurrency control
	maxConcurrency int
}

// NewProofManager creates a new proof manager with optimized memory usage
// If objectPool is nil, it will use the default global pool
func NewProofManager(objectPool *ObjectPool, maxCacheSize, maxConcurrency int) *ProofManager {
	if objectPool == nil {
		objectPool = defaultPool
	}
	
	if maxCacheSize <= 0 {
		maxCacheSize = 100 // Default cache size
	}
	
	if maxConcurrency <= 0 {
		maxConcurrency = 4 // Default concurrency
	}
	
	return &ProofManager{
		tempPool:       objectPool,
		maxCacheSize:   maxCacheSize,
		maxConcurrency: maxConcurrency,
	}
}

// Default singleton manager
var defaultProofManager = NewProofManager(nil, 0, 0)

// CreateProofWithPooling creates a zero-knowledge proof with optimized memory usage
func (pm *ProofManager) CreateProofWithPooling(
	publicKey *PublicKey,
	signature *Signature,
	messages []*big.Int,
	disclosedIndices []int,
	header []byte,
) (*ProofOfKnowledge, map[int]*big.Int, error) {
	// Validate inputs
	if len(messages) != publicKey.MessageCount {
		return nil, nil, ErrInvalidMessageCount
	}
	
	// Get a map for faster lookup of disclosed indices from the pool
	disclosedMap := pm.tempPool.GetDisclosedMsgMap()
	defer pm.tempPool.PutDisclosedMsgMap(disclosedMap)
	
	for _, idx := range disclosedIndices {
		disclosedMap[idx] = big.NewInt(1)
	}
	
	// Create a map of disclosed messages (reusing the pool)
	disclosedMessages := pm.tempPool.GetDisclosedMsgMap()
	
	// We don't defer putting it back because we return it to the caller
	// They should eventually call PutDisclosedMsgMap when done with it
	
	for _, idx := range disclosedIndices {
		if idx < 0 || idx >= len(messages) {
			// Clean up before returning error
			pm.tempPool.PutDisclosedMsgMap(disclosedMessages)
			return nil, nil, fmt.Errorf("invalid disclosed index: %d", idx)
		}
		// Make a copy to avoid potential reference issues
		disclosedMessages[idx] = new(big.Int).Set(messages[idx])
	}
	
	// Calculate domain
	_ =  pm.getDomainCached(publicKey, header)
	
	// Generate randomness r for signature blinding
	r, err := ConstantTimeRandom(rand.Reader, Order)
	if err != nil {
		// Clean up before returning error
		pm.tempPool.PutDisclosedMsgMap(disclosedMessages)
		return nil, nil, fmt.Errorf("failed to generate random value: %w", err)
	}
	
	// Compute A' = A * g1^r
	// Use pooled resources for computation
	APrimeJac := pm.tempPool.GetG1Jac()
	defer pm.tempPool.PutG1Jac(APrimeJac)
	
	APrimeJac.FromAffine(&signature.A)
	
	g1rJac := pm.tempPool.GetG1Jac()
	defer pm.tempPool.PutG1Jac(g1rJac)
	
	g1rJac.FromAffine(&publicKey.G1)
	g1rJac.ScalarMultiplication(g1rJac, r)
	APrimeJac.AddAssign(g1rJac)
	
	// Convert to affine
	APrime := g1JacToAffine(*APrimeJac)
	
	// Compute A-bar = A' * B^r
	ABarJac := pm.tempPool.GetG1Jac()
	defer pm.tempPool.PutG1Jac(ABarJac)
	
	// Initialize A-bar with A'
	ABarJac.FromAffine(&APrime)
	
	// Compute blinded messages contribution to A-bar
	// Use a single pooled point that gets reused
	pointJac := pm.tempPool.GetG1Jac()
	defer pm.tempPool.PutG1Jac(pointJac)
	
	for i := 0; i < len(messages); i++ {
		if val, ok := disclosedMap[i]; ok && val != nil {
			continue // Skip disclosed messages
		}
		
		// Compute h_i^{m_i * r} for hidden messages
		msg := messages[i]
		
		// Get a temporary big.Int from the pool
		mr := pm.tempPool.GetBigInt()
		mr.Mul(msg, r)
		mr.Mod(mr, Order)
		
		// Compute h_i^{m_i * r}
		pointJac.FromAffine(&publicKey.H[i+2]) // +2 for Q1, Q2
		pointJac.ScalarMultiplication(pointJac, mr)
		ABarJac.AddAssign(pointJac)
		
		// Return temporary value to pool
		pm.tempPool.PutBigInt(mr)
	}
	
	// Convert to affine
	ABar := g1JacToAffine(*ABarJac)
	
	// Generate random blinding factors
	eBlind, err := ConstantTimeRandom(rand.Reader, Order)
	if err != nil {
		// Clean up before returning error
		pm.tempPool.PutDisclosedMsgMap(disclosedMessages)
		return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
	}
	
	sBlind, err := ConstantTimeRandom(rand.Reader, Order)
	if err != nil {
		// Clean up before returning error
		pm.tempPool.PutDisclosedMsgMap(disclosedMessages)
		return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
	}
	
	// Generate blinding factor for domain
	domainBlind, err := ConstantTimeRandom(rand.Reader, Order)
	if err != nil {
		// Clean up before returning error
		pm.tempPool.PutDisclosedMsgMap(disclosedMessages)
		return nil, nil, fmt.Errorf("failed to generate domain blinding: %w", err)
	}
	
	// Create blinding factors for undisclosed messages
	mBlind := make(map[int]*big.Int)
	for i := 0; i < len(messages); i++ {
		if _, ok := disclosedMap[i]; !ok {
			mBlind[i], err = ConstantTimeRandom(rand.Reader, Order)
			if err != nil {
				// Clean up before returning error
				pm.tempPool.PutDisclosedMsgMap(disclosedMessages)
				return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
			}
		}
	}
	
	// Compute commitment D = Q1^sBlind * Q2^domainBlind * ∏(H_i^mBlind_i) for all undisclosed i
	// Use pooled resources for computation
	DJac := pm.tempPool.GetG1Jac()
	defer pm.tempPool.PutG1Jac(DJac)
	
	// Start with Q1^sBlind
	tempJac := pm.tempPool.GetG1Jac()
	defer pm.tempPool.PutG1Jac(tempJac)
	
	tempJac.FromAffine(&publicKey.H[0])
	tempJac.ScalarMultiplication(tempJac, sBlind)
	DJac.Set(tempJac)
	
	// Add Q2^domainBlind
	tempJac.FromAffine(&publicKey.H[1])
	tempJac.ScalarMultiplication(tempJac, domainBlind)
	DJac.AddAssign(tempJac)
	
	// Add H_i^mBlind_i for each undisclosed message
	for i := 0; i < len(messages); i++ {
		if _, ok := disclosedMap[i]; !ok {
			tempJac.FromAffine(&publicKey.H[i+2]) // +2 for Q1, Q2
			tempJac.ScalarMultiplication(tempJac, mBlind[i])
			DJac.AddAssign(tempJac)
		}
	}
	
	// Convert to affine
	D := g1JacToAffine(*DJac)
	
	// Compute the Fiat-Shamir challenge c
	c := ComputeProofChallenge(APrime, ABar, D, disclosedIndices, disclosedMessages)
	
	// Compute e^ = e*c + eBlind
	eHat := pm.tempPool.GetBigInt()
	eHat.Mul(signature.E, c)
	eHat.Add(eHat, eBlind)
	eHat.Mod(eHat, Order)
	
	// Compute s^ = s*c + sBlind
	sHat := pm.tempPool.GetBigInt()
	sHat.Mul(signature.S, c)
	sHat.Add(sHat, sBlind)
	sHat.Mod(sHat, Order)
	
	// Compute m_i^ = m_i*c + mBlind_i for each undisclosed message
	mHat := make(map[int]*big.Int)
	
	// Temporary value for calculation
	temp := pm.tempPool.GetBigInt()
	defer pm.tempPool.PutBigInt(temp)
	
	for i := 0; i < len(messages); i++ {
		if _, ok := disclosedMap[i]; !ok {
			temp.Mul(messages[i], c)
			mHat[i] = new(big.Int).Add(temp, mBlind[i])
			mHat[i].Mod(mHat[i], Order)
		}
	}
	
	// Create the final proof
	proof := &ProofOfKnowledge{
		APrime: APrime,
		ABar:   ABar,
		D:      D,
		C:      new(big.Int).Set(c), // Make a copy to avoid reference issues
		EHat:   eHat,
		SHat:   sHat,
		MHat:   mHat,
	}
	
	return proof, disclosedMessages, nil
}

// VerifyProofWithPooling verifies a zero-knowledge proof with optimized memory usage
func (pm *ProofManager) VerifyProofWithPooling(
	publicKey *PublicKey,
	proof *ProofOfKnowledge,
	disclosedMessages map[int]*big.Int,
	header []byte,
) error {
	// Validate inputs
	for idx := range disclosedMessages {
		if idx < 0 || idx >= publicKey.MessageCount {
			return fmt.Errorf("invalid disclosed message index: %d", idx)
		}
	}
	
	// Recompute the challenge to verify correct formation
	// Get the indices for disclosed messages
	disclosedIndices := make([]int, 0, len(disclosedMessages))
	for idx := range disclosedMessages {
		disclosedIndices = append(disclosedIndices, idx)
	}
	
	// Sort indices for deterministic challenge computation
	sort.Ints(disclosedIndices)
	
	// Compute the challenge
	c := ComputeProofChallenge(proof.APrime, proof.ABar, proof.D, disclosedIndices, disclosedMessages)
	
	// Check if the computed challenge matches the one in the proof
	if !ConstantTimeEq(c, proof.C) {
		return ErrInvalidSignature
	}
	
	// Calculate domain value
	domain := pm.getDomainCached(publicKey, header)
	
	// Use pooled slices for point collection
	totalPoints := 3 + len(disclosedMessages) + len(proof.MHat) + 1
	points := pm.tempPool.GetG1AffineSlice(totalPoints)
	defer pm.tempPool.PutG1AffineSlice(points)
	
	scalars := pm.tempPool.GetScalarSlice(totalPoints)
	defer pm.tempPool.PutScalarSlice(scalars)
	
	// This is used for e(B, P2) = e(A', W)*e(A', P2)^e^
	// Start with P1 (g1)
	points = append(points, publicKey.G1)
	scalars = append(scalars, big.NewInt(1))
	
	// Add Q1*S^
	points = append(points, publicKey.H[0])
	scalars = append(scalars, proof.SHat)
	
	// Add Q2*domain
	points = append(points, publicKey.H[1])
	scalars = append(scalars, domain)
	
	// Add each H_i*m_i for disclosed messages
	for idx, msg := range disclosedMessages {
		// For disclosed messages, we use the disclosed value directly
		points = append(points, publicKey.H[idx+2]) // +2 for Q1, Q2
		scalars = append(scalars, msg)
	}
	
	// Add each H_i*m_i^ for undisclosed messages
	for idx, msgHat := range proof.MHat {
		points = append(points, publicKey.H[idx+2]) // +2 for Q1, Q2
		scalars = append(scalars, msgHat)
	}
	
	// Subtract D*c (add D*(-c))
	points = append(points, proof.D)
	
	// Get a temporary big.Int for the negated challenge
	negC := pm.tempPool.GetBigInt()
	negC.Neg(proof.C)
	negC.Mod(negC, Order)
	scalars = append(scalars, negC)
	
	// Perform multi-scalar multiplication
	g1bJac := pm.tempPool.GetG1Jac()
	defer pm.tempPool.PutG1Jac(g1bJac)
	
	// Use our implementation for MSM
	result, err := MultiScalarMulG1(points, scalars)
	if err != nil {
		// Clean up before returning error
		pm.tempPool.PutBigInt(negC)
		return fmt.Errorf("failed multi-scalar multiplication: %w", err)
	}
	
	// Convert to g1bJac for further operations
	*g1bJac = result
	
	// Convert to affine
	g1b := g1JacToAffine(*g1bJac)
	
	// Return temporary values to the pool
	pm.tempPool.PutBigInt(negC)
	
	// Now compute T = ABar^c * D using multi-scalar multiplication
	TPoints := pm.tempPool.GetG1AffineSlice(2)
	defer pm.tempPool.PutG1AffineSlice(TPoints)
	
	TPoints = append(TPoints, proof.ABar, proof.D)
	
	// Create scalars (C and 1)
	one := pm.tempPool.GetBigInt().SetInt64(1)
	defer pm.tempPool.PutBigInt(one)
	
	TScalars := pm.tempPool.GetScalarSlice(2)
	defer pm.tempPool.PutScalarSlice(TScalars)
	
	TScalars = append(TScalars, proof.C, one)
	
	// Perform multi-scalar multiplication
	TJac := pm.tempPool.GetG1Jac()
	defer pm.tempPool.PutG1Jac(TJac)
	
	// Use our implementation for MSM
	result, err = MultiScalarMulG1(TPoints, TScalars)
	if err != nil {
		return fmt.Errorf("failed multi-scalar multiplication: %w", err)
	}
	
	// Assign the result
	*TJac = result
	
	// Convert to affine
	T := g1JacToAffine(*TJac)
	
	// e(APrime, W) * e(g1b, -g2) * e(T, g2) = 1
	
	// Negate g2 for the second pairing
	negG2Jac := pm.tempPool.GetG2Jac()
	defer pm.tempPool.PutG2Jac(negG2Jac)
	
	negG2Jac.FromAffine(&publicKey.G2)
	negG2Jac.Neg(negG2Jac)
	negG2 := g2JacToAffine(*negG2Jac)
	
	// Use pooled slices for pairing computation
	g1PairingPoints := pm.tempPool.GetG1AffineSlice(3)
	defer pm.tempPool.PutG1AffineSlice(g1PairingPoints)
	
	g1PairingPoints = append(g1PairingPoints, proof.APrime, g1b, T)
	
	g2PairingPoints := pm.tempPool.GetG2AffineSlice(3)
	defer pm.tempPool.PutG2AffineSlice(g2PairingPoints)
	
	g2PairingPoints = append(g2PairingPoints, publicKey.W, negG2, publicKey.G2)
	
	// Check pairing equation: e(APrime, W) * e(g1b, -g2) * e(T, g2) = 1
	pairingResult, err := bls12381.Pair(g1PairingPoints, g2PairingPoints)
	if err != nil {
		return ErrPairingFailed
	}
	
	// Check if the pairing result is 1
	if !pairingResult.IsOne() {
		return ErrInvalidSignature
	}
	
	return nil
}

// ExtendProofWithPooling extends an existing proof to disclose additional attributes with optimized memory usage
func (pm *ProofManager) ExtendProofWithPooling(
	proof *ProofOfKnowledge,
	disclosedMessages map[int]*big.Int,
	additionalIndices []int,
	secretMessages map[int]*big.Int,
	publicKey *PublicKey,
) (*ProofOfKnowledge, map[int]*big.Int, error) {
	// Validate inputs
	for _, idx := range additionalIndices {
		if _, ok := disclosedMessages[idx]; ok {
			return nil, nil, fmt.Errorf("message at index %d is already disclosed", idx)
		}
		
		if _, ok := secretMessages[idx]; !ok {
			return nil, nil, fmt.Errorf("secret message at index %d not provided", idx)
		}
		
		if idx < 0 || idx >= publicKey.MessageCount {
			return nil, nil, fmt.Errorf("invalid message index: %d", idx)
		}
	}
	
	// Create the new disclosed messages map
	newDisclosedMessages := pm.tempPool.GetDisclosedMsgMap()
	
	// We don't defer putting it back because we return it to the caller
	// They should eventually call PutDisclosedMsgMap when done with it
	
	for idx, msg := range disclosedMessages {
		newDisclosedMessages[idx] = new(big.Int).Set(msg)
	}
	
	// Add the additional messages
	for _, idx := range additionalIndices {
		newDisclosedMessages[idx] = new(big.Int).Set(secretMessages[idx])
	}
	
	// Generate the new blinding factors
	e, err := ConstantTimeRandom(rand.Reader, Order)
	if err != nil {
		// Clean up before returning error
		pm.tempPool.PutDisclosedMsgMap(newDisclosedMessages)
		return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
	}
	
	s, err := ConstantTimeRandom(rand.Reader, Order)
	if err != nil {
		// Clean up before returning error
		pm.tempPool.PutDisclosedMsgMap(newDisclosedMessages)
		return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
	}
	
	// Prepare the commitment for newly disclosed messages
	// Use pooled objects for computation
	ABarJac := pm.tempPool.GetG1Jac()
	defer pm.tempPool.PutG1Jac(ABarJac)
	
	ABarJac.FromAffine(&proof.ABar)
	
	// Reuse a single point for all operations
	pointJac := pm.tempPool.GetG1Jac()
	defer pm.tempPool.PutG1Jac(pointJac)
	
	// For each newly disclosed message, remove it from blinding
	for _, idx := range additionalIndices {
		// Get the message value
		msg := secretMessages[idx]
		
		// Compute h_i^(-msg * C)
		pointJac.FromAffine(&publicKey.H[idx+2]) // +2 for Q1, Q2
		
		// Compute -msg * C using a pooled big.Int
		negMsgC := pm.tempPool.GetBigInt()
		negMsgC.Mul(msg, proof.C)
		negMsgC.Neg(negMsgC)
		negMsgC.Mod(negMsgC, Order)
		
		// Compute h_i^(-msg * C)
		pointJac.ScalarMultiplication(pointJac, negMsgC)
		
		// Update ABar: ABar = ABar * h_i^(-msg * C)
		ABarJac.AddAssign(pointJac)
		
		// Return temporary value to pool
		pm.tempPool.PutBigInt(negMsgC)
	}
	
	// Convert to affine
	newABar := g1JacToAffine(*ABarJac)
	
	// Generate a new challenge value
	c := ComputeProofChallenge(
		proof.APrime,
		newABar,
		proof.D,
		additionalIndices,
		newDisclosedMessages,
	)
	
	// Compute the final proof with E' = E + e
	eHat := pm.tempPool.GetBigInt()
	eHat.Add(proof.EHat, e)
	eHat.Mod(eHat, Order)
	
	// Compute S' = S + s
	sHat := pm.tempPool.GetBigInt()
	sHat.Add(proof.SHat, s)
	sHat.Mod(sHat, Order)
	
	// Create the new proof
	newProof := &ProofOfKnowledge{
		APrime: proof.APrime,
		ABar:   newABar,
		D:      proof.D,
		C:      new(big.Int).Set(c), // Make a copy to avoid reference issues
		EHat:   eHat,
		SHat:   sHat,
		MHat:   make(map[int]*big.Int),
	}
	
	// Copy MHat values except for newly disclosed messages
	for idx, val := range proof.MHat {
		if !contains(additionalIndices, idx) {
			newProof.MHat[idx] = new(big.Int).Set(val)
		}
	}
	
	return newProof, newDisclosedMessages, nil
}

// Helper to check if an int slice contains a value
func contains(s []int, val int) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}
	return false
}

// Domain calculation with caching
func (pm *ProofManager) getDomainCached(pk *PublicKey, header []byte) *big.Int {
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
	if cached, ok := pm.domainCache.Load(key); ok {
		return cached.(*big.Int)
	}
	
	// Not in cache, calculate it
	domain := CalculateDomain(pk, header)
	
	// Store in cache
	pm.domainCache.Store(key, domain)
	
	// Check if we need to clean up the cache
	pm.cleanupCacheIfNeeded()
	
	return domain
}

// Cleanup cache if it gets too large
func (pm *ProofManager) cleanupCacheIfNeeded() {
	var count int
	
	// Count entries (inefficient but sync.Map doesn't provide a direct size method)
	pm.domainCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	
	// If cache is too large, clear it
	if count > pm.maxCacheSize {
		pm.mu.Lock()
		defer pm.mu.Unlock()
		
		// Create a new map
		pm.domainCache = sync.Map{}
	}
}

// Global convenience functions using the default manager

// CreateProofWithPooling creates a zero-knowledge proof with optimized memory usage
func CreateProofWithPooling(
	publicKey *PublicKey,
	signature *Signature,
	messages []*big.Int,
	disclosedIndices []int,
	header []byte,
) (*ProofOfKnowledge, map[int]*big.Int, error) {
	return defaultProofManager.CreateProofWithPooling(publicKey, signature, messages, disclosedIndices, header)
}

// VerifyProofWithPooling verifies a zero-knowledge proof with optimized memory usage
func VerifyProofWithPooling(
	publicKey *PublicKey,
	proof *ProofOfKnowledge,
	disclosedMessages map[int]*big.Int,
	header []byte,
) error {
	return defaultProofManager.VerifyProofWithPooling(publicKey, proof, disclosedMessages, header)
}

// ExtendProofWithPooling extends a proof to reveal additional attributes with optimized memory usage
func ExtendProofWithPooling(
	proof *ProofOfKnowledge,
	disclosedMessages map[int]*big.Int,
	additionalIndices []int,
	secretMessages map[int]*big.Int,
	publicKey *PublicKey,
) (*ProofOfKnowledge, map[int]*big.Int, error) {
	return defaultProofManager.ExtendProofWithPooling(proof, disclosedMessages, additionalIndices, secretMessages, publicKey)
}

// ExtendProof extends a proof to reveal additional attributes
// This is a wrapper for ExtendProofWithPooling which is a more memory-efficient implementation
func ExtendProof(
	proof *ProofOfKnowledge,
	disclosedMessages map[int]*big.Int,
	additionalIndices []int,
	secretMessages map[int]*big.Int,
	publicKey *PublicKey,
) (*ProofOfKnowledge, map[int]*big.Int, error) {
	return ExtendProofWithPooling(proof, disclosedMessages, additionalIndices, secretMessages, publicKey)
}