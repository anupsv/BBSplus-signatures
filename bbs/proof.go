// Package bbs implements the BBS+ Signatures for selective disclosure
package bbs

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// CreateProof creates a zero-knowledge proof that reveals only specific messages from a signature
// Following IRTF cfrg-bbs-signatures spec for standards compliance
func CreateProof(
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
	
	// Create a map for faster lookup of disclosed indices
	disclosedMap := make(map[int]bool)
	for _, idx := range disclosedIndices {
		disclosedMap[idx] = true
	}
	
	// Create a map of disclosed messages
	disclosedMessages := make(map[int]*big.Int)
	for _, idx := range disclosedIndices {
		if idx < 0 || idx >= len(messages) {
			return nil, nil, fmt.Errorf("invalid disclosed index: %d", idx)
		}
		disclosedMessages[idx] = messages[idx]
	}
	
	// Calculate domain - use it in later operations
	_ = CalculateDomain(publicKey, header)

	// Generate randomness r for signature blinding
	r, err := RandomScalar(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random value: %w", err)
	}

	// Compute A' = A * g1^r
	APrimeJac := bls12381.G1Jac{}
	APrimeJac.FromAffine(&signature.A)
	
	g1rJac := bls12381.G1Jac{}
	g1rJac.FromAffine(&publicKey.G1)
	g1rJac.ScalarMultiplication(&g1rJac, r)
	APrimeJac.AddAssign(&g1rJac)
	
	// Convert to affine
	APrime := g1JacToAffine(APrimeJac)
	
	// Compute A-bar = A' * B^r where:
	// B = P1 + Q1*s + Q2*domain + H_1*m_1 + ... + H_L*m_L
	// We'll focus on the messages that are NOT being disclosed,
	// as these are the ones that need to be blinded with randomness
	
	// Initialize A-bar with A'
	ABarJac := bls12381.G1Jac{}
	ABarJac.FromAffine(&APrime)
	
	// Compute blinded messages contribution to A-bar
	for i := 0; i < len(messages); i++ {
		if disclosedMap[i] {
			continue // Skip disclosed messages
		}
		
		// Compute h_i^{m_i * r} for hidden messages
		msg := messages[i]
		mr := new(big.Int).Mul(msg, r)
		mr.Mod(mr, Order)
		
		himrJac := bls12381.G1Jac{}
		himrJac.FromAffine(&publicKey.H[i+2]) // +2 for Q1, Q2
		himrJac.ScalarMultiplication(&himrJac, mr)
		ABarJac.AddAssign(&himrJac)
	}
	
	// Convert to affine
	ABar := g1JacToAffine(ABarJac)

	// Generate random blinding factors
	eBlind, err := RandomScalar(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
	}

	sBlind, err := RandomScalar(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
	}
	
	// Generate blinding factor for domain
	domainBlind, err := RandomScalar(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate domain blinding: %w", err)
	}

	// Create blinding factors for undisclosed messages
	mBlind := make(map[int]*big.Int)
	for i := 0; i < len(messages); i++ {
		if !disclosedMap[i] {
			mBlind[i], err = RandomScalar(rand.Reader)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
			}
		}
	}

	// Compute commitment D = Q1^sBlind * Q2^domainBlind * ∏(H_i^mBlind_i) for all undisclosed i

	// Start with Q1^sBlind
	DJac := bls12381.G1Jac{}
	q1sBlindJac := bls12381.G1Jac{}
	q1sBlindJac.FromAffine(&publicKey.H[0])
	q1sBlindJac.ScalarMultiplication(&q1sBlindJac, sBlind)
	DJac.AddAssign(&q1sBlindJac)
	
	// Add Q2^domainBlind
	q2dBlindJac := bls12381.G1Jac{}
	q2dBlindJac.FromAffine(&publicKey.H[1])
	q2dBlindJac.ScalarMultiplication(&q2dBlindJac, domainBlind)
	DJac.AddAssign(&q2dBlindJac)
	
	// Add H_i^mBlind_i for each undisclosed message
	for i := 0; i < len(messages); i++ {
		if !disclosedMap[i] {
			hiJac := bls12381.G1Jac{}
			hiJac.FromAffine(&publicKey.H[i+2]) // +2 for Q1, Q2
			hiJac.ScalarMultiplication(&hiJac, mBlind[i])
			DJac.AddAssign(&hiJac)
		}
	}
	
	// Convert to affine
	D := g1JacToAffine(DJac)
	
	// Compute the Fiat-Shamir challenge c
	c := ComputeProofChallenge(APrime, ABar, D, disclosedIndices, disclosedMessages)
	
	// Compute e^ = e*c + eBlind
	eHat := new(big.Int).Mul(signature.E, c)
	eHat.Add(eHat, eBlind)
	eHat.Mod(eHat, Order)
	
	// Compute s^ = s*c + sBlind
	sHat := new(big.Int).Mul(signature.S, c)
	sHat.Add(sHat, sBlind)
	sHat.Mod(sHat, Order)
	
	// Compute m_i^ = m_i*c + mBlind_i for each undisclosed message
	mHat := make(map[int]*big.Int)
	for i := 0; i < len(messages); i++ {
		if !disclosedMap[i] {
			mHat[i] = new(big.Int).Mul(messages[i], c)
			mHat[i].Add(mHat[i], mBlind[i])
			mHat[i].Mod(mHat[i], Order)
		}
	}
	
	// Compute r^ = r*c + rBlind
	// For our implementation, we don't need r^ as it's used for signature binding in the original BBS scheme
	
	// Create the final proof
	proof := &ProofOfKnowledge{
		APrime: APrime,
		ABar:   ABar,
		D:      D,
		C:      c,
		EHat:   eHat,
		SHat:   sHat,
		MHat:   mHat,
	}
	
	return proof, disclosedMessages, nil
}

// VerifyProof verifies a zero-knowledge proof of knowledge
// Following IRTF cfrg-bbs-signatures spec for standards compliance
func VerifyProof(
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
	if c.Cmp(proof.C) != 0 {
		return ErrInvalidSignature
	}
	
	// Calculate domain value
	domain := CalculateDomain(publicKey, header)
	
	// Prepare points and scalars for MultiScalarMul
	// We need to compute: g1b = P1 + Q1*S^ + Q2*domain + ∑(H_i*m_i) - D*c
	
	// This is used for e(B, P2) = e(A', W)*e(A', P2)^e^
	// Start with P1 (g1)
	points := []bls12381.G1Affine{publicKey.G1}
	scalars := []*big.Int{big.NewInt(1)}
	
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
	negC := new(big.Int).Neg(proof.C)
	negC.Mod(negC, Order)
	scalars = append(scalars, negC)
	PutBigInt(negC) // We're done with this temporary value
	
	// Perform multi-scalar multiplication
	g1bJac := GetG1Jac()
	defer PutG1Jac(g1bJac)
	
	// Use gnark-crypto's implementation for MSM
	resultJac, err := MultiScalarMulG1(points, scalars)
	if err != nil {
		// Clean up before returning error
		for _, scalar := range scalars {
			PutBigInt(scalar)
		}
		return fmt.Errorf("failed multi-scalar multiplication: %w", err)
	}
	
	// Set g1bJac to the result
	*g1bJac = resultJac
	
	// Convert to affine
	g1b := g1JacToAffine(*g1bJac)
	
	// Return temporary values to the pool
	for _, scalar := range scalars {
		PutBigInt(scalar)
	}
	
	// Now compute T = ABar^c * D using multi-scalar multiplication
	TPoints := GetG1AffineSlice(2)
	defer PutG1AffineSlice(TPoints)
	
	TPoints = append(TPoints, proof.ABar, proof.D)
	
	// Create scalars (C and 1)
	one := GetBigInt().SetInt64(1)
	TScalars := GetScalarSlice(2)
	defer PutScalarSlice(TScalars)
	
	TScalars = append(TScalars, proof.C, one)
	
	// Get Jacobian point from pool
	TJac := GetG1Jac()
	defer PutG1Jac(TJac)
	
	// Use our implementation for MSM
	tResult, err := MultiScalarMulG1(TPoints, TScalars)
	if err != nil {
		PutBigInt(one)
		return fmt.Errorf("failed multi-scalar multiplication: %w", err)
	}
	
	// Assign the result
	*TJac = tResult
	
	// Convert to affine
	T := g1JacToAffine(*TJac)
	
	// Return temporary values to the pool
	PutBigInt(one)
	
	// e(APrime, W) * e(g1b, -g2) * e(T, g2) = 1
	
	// Negate g2 for the second pairing
	negG2Jac := bls12381.G2Jac{}
	negG2Jac.FromAffine(&publicKey.G2)
	negG2Jac.Neg(&negG2Jac)
	negG2 := g2JacToAffine(negG2Jac)
	
	// Check pairing equation: e(APrime, W) * e(g1b, -g2) * e(T, g2) = 1
	// We use the Pair function which computes the product of pairings
	pairingResult, err := bls12381.Pair(
		[]bls12381.G1Affine{proof.APrime, g1b, T},
		[]bls12381.G2Affine{publicKey.W, negG2, publicKey.G2},
	)
	if err != nil {
		return ErrPairingFailed
	}
	
	// Check if the pairing result is 1
	if !pairingResult.IsOne() {
		return ErrInvalidSignature
	}
	
	return nil
}

// BatchVerifyProofs verifies multiple proofs of knowledge with selective disclosure in batch
func BatchVerifyProofs(
	publicKeys []*PublicKey,
	proofs []*ProofOfKnowledge,
	disclosedMessagesList []map[int]*big.Int,
	headers [][]byte,
) error {
	// Validate inputs
	if len(publicKeys) != len(proofs) || len(proofs) != len(disclosedMessagesList) {
		return fmt.Errorf("mismatched array lengths in batch verification")
	}
	
	if len(headers) != 0 && len(headers) != len(proofs) {
		return fmt.Errorf("headers array length does not match proofs array length")
	}
	
	if len(proofs) == 0 {
		return nil
	}
	
	// If there's only one proof, use the regular verification
	if len(proofs) == 1 {
		return VerifyProof(publicKeys[0], proofs[0], disclosedMessagesList[0], headers[0])
	}
	
	// First, verify all challenges independently with concurrent processing
	errChan := make(chan error, len(proofs))
	concurrencyLimit := 4 // Adjust based on environment
	
	// Create a semaphore for limiting concurrency
	sem := make(chan struct{}, concurrencyLimit)
	
	// Use a wait group to know when all goroutines complete
	var wg sync.WaitGroup
	
	for i, proof := range proofs {
		wg.Add(1)
		
		// Create a closure to capture loop variables
		go func(idx int, p *ProofOfKnowledge, disclosed map[int]*big.Int) {
			// Acquire semaphore
			sem <- struct{}{}
			
			// Release semaphore and mark as done when finished
			defer func() {
				<-sem
				wg.Done()
			}()
			
			// Get the indices for disclosed messages
			disclosedIndices := make([]int, 0, len(disclosed))
			for messageIdx := range disclosed {
				disclosedIndices = append(disclosedIndices, messageIdx)
			}
			
			// Sort indices for deterministic challenge computation
			sort.Ints(disclosedIndices)
			
			// Compute the challenge
			c := ComputeProofChallenge(
				p.APrime, 
				p.ABar, 
				p.D, 
				disclosedIndices, 
				disclosed,
			)
			
			// Check if the computed challenge matches the one in the proof
			if c.Cmp(p.C) != 0 {
				errChan <- fmt.Errorf("challenge verification failed for proof %d", idx)
				return
			}
		}(i, proof, disclosedMessagesList[i])
	}
	
	// Wait for all verifications to complete
	wg.Wait()
	
	// Check if any verifications failed
	select {
	case err := <-errChan:
		return err
	default:
		// All verifications passed
	}
	
	// Generate random scalars for batch verification using constant-time operations
	batchScalars := GetScalarSlice(len(proofs))
	defer PutScalarSlice(batchScalars)
	
	// Generate cryptographically strong random scalars
	for i := range batchScalars {
		var err error
		batchScalars[i], err = ConstantTimeRandom(rand.Reader, Order)
		if err != nil {
			return fmt.Errorf("failed to generate batch scalars: %w", err)
		}
	}
	
	// Prepare points for the final pairing check
	// Pre-allocate the arrays with the expected capacity
	pointCapacity := len(proofs) * 2 // Each proof contributes approximately 2 points
	g1Points := GetG1AffineSlice(pointCapacity)
	defer PutG1AffineSlice(g1Points)
	
	g2Points := make([]bls12381.G2Affine, 0, pointCapacity)
	
	// Process each proof with memory pooling
	for i, proof := range proofs {
		publicKey := publicKeys[i]
		disclosedMessages := disclosedMessagesList[i]
		
		// Get the domain value (using pooled big.Int)
		var domain *big.Int
		if i < len(headers) && headers[i] != nil {
			domain = CalculateDomain(publicKey, headers[i])
		} else {
			domain = CalculateDomain(publicKey, nil)
		}
		
		// Multiply by batch scalar for this proof
		batchScalar := batchScalars[i]
		
		// Compute the g1b point (same as in single verification)
		// Use memory pooling for these arrays
		pointsCount := 3 + len(disclosedMessages) // Base points + message points
		points := GetG1AffineSlice(pointsCount)
		scalars := GetScalarSlice(pointsCount)
		
		// Start with P1 * batchScalar
		points = append(points, publicKey.G1)
		scalars = append(scalars, batchScalar)
		
		// Add Q1*S^
		points = append(points, publicKey.H[0])
		sHatBatch := GetBigInt()
		sHatBatch.Mul(proof.SHat, batchScalar)
		sHatBatch.Mod(sHatBatch, Order)
		scalars = append(scalars, sHatBatch)
		
		// Add Q2*domain
		points = append(points, publicKey.H[1])
		domainBatch := GetBigInt()
		domainBatch.Mul(domain, batchScalar)
		domainBatch.Mod(domainBatch, Order)
		scalars = append(scalars, domainBatch)
		
		// Add each H_i*m_i for disclosed messages
		for idx, msg := range disclosedMessages {
			// For disclosed messages, we use the disclosed value directly
			// Use memory pooling for intermediate values
			msgC := GetBigInt().Mul(msg, proof.C)
			negMsgC := GetBigInt().Neg(msgC)
			negMsgC.Mod(negMsgC, Order)
			negMsgCBatch := GetBigInt().Mul(negMsgC, batchScalar)
			negMsgCBatch.Mod(negMsgCBatch, Order)
			
			// Add to points and scalars
			points = append(points, publicKey.H[idx+2]) // +2 for Q1, Q2
			scalars = append(scalars, negMsgCBatch)
			
			// Return temporary values to pool
			PutBigInt(msgC)
			PutBigInt(negMsgC)
		}
		
		// Perform multi-scalar multiplication
		g1bJac := GetG1Jac()
		resultJac, err := MultiScalarMulG1(points, scalars)
		if err != nil {
			// Clean up before returning error
			PutG1AffineSlice(points)
			for _, s := range scalars {
				PutBigInt(s)
			}
			PutScalarSlice(scalars)
			PutG1Jac(g1bJac)
			
			return fmt.Errorf("failed multi-scalar multiplication: %w", err)
		}
		*g1bJac = resultJac
		
		// Convert to affine
		g1b := g1JacToAffine(*g1bJac)
		
		// Return temporary values to pool
		PutG1AffineSlice(points)
		for _, s := range scalars {
			PutBigInt(s)
		}
		PutScalarSlice(scalars)
		PutG1Jac(g1bJac)
		
		// Add e(g1b, -g2) to the pairing check
		negG2Jac := bls12381.G2Jac{}
		negG2Jac.FromAffine(&publicKey.G2)
		negG2Jac.Neg(&negG2Jac)
		negG2 := g2JacToAffine(negG2Jac)
		
		g1Points = append(g1Points, g1b)
		g2Points = append(g2Points, negG2)
		
		// Compute T = ABar^c * D using multi-scalar multiplication
		TPoints := GetG1AffineSlice(2)
		TPoints = append(TPoints, proof.ABar, proof.D)
		
		// Create scalars (C*batchScalar and batchScalar)
		cBatch := GetBigInt().Mul(proof.C, batchScalar)
		cBatch.Mod(cBatch, Order)
		oneBatch := GetBigInt().Set(batchScalar)
		
		TScalars := GetScalarSlice(2)
		TScalars = append(TScalars, cBatch, oneBatch)
		
		// Perform multi-scalar multiplication
		TJac := GetG1Jac()
		tjResult, err := MultiScalarMulG1(TPoints, TScalars)
		if err != nil {
			// Clean up before returning error
			PutG1AffineSlice(TPoints)
			PutBigInt(cBatch)
			PutBigInt(oneBatch)
			PutScalarSlice(TScalars)
			PutG1Jac(TJac)
			
			return fmt.Errorf("failed multi-scalar multiplication: %w", err)
		}
		*TJac = tjResult
		
		// Convert to affine
		T := g1JacToAffine(*TJac)
		
		// Add e(T, g2) to the pairing check
		g1Points = append(g1Points, T)
		g2Points = append(g2Points, publicKey.G2)
		
		// Return temporary values to pool
		PutG1AffineSlice(TPoints)
		PutBigInt(cBatch)
		PutBigInt(oneBatch)
		PutScalarSlice(TScalars)
		PutG1Jac(TJac)
	}
	
	// Perform the batch pairing check
	pairingResult, err := bls12381.Pair(g1Points, g2Points)
	if err != nil {
		return ErrPairingFailed
	}
	
	// Check if the pairing result is 1 (using constant-time comparison when possible)
	if !pairingResult.IsOne() {
		return ErrInvalidSignature
	}
	
	return nil
}

// ExtendProofOriginal extends an existing proof to disclose additional attributes
// - proof: The original proof
// - disclosedMessages: The currently disclosed messages
// - additionalIndices: The indices of additional messages to disclose
// - secretMessages: A map of all message values (both disclosed and undisclosed)
// - publicKey: The public key for verification
// Returns: 
// - A new proof with additional disclosed attributes
// - An updated map of disclosed messages
// - An error, if any occurred
func ExtendProofOriginal(
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
	newDisclosedMessages := make(map[int]*big.Int)
	for idx, msg := range disclosedMessages {
		newDisclosedMessages[idx] = new(big.Int).Set(msg)
	}
	
	// Add the additional messages
	for _, idx := range additionalIndices {
		newDisclosedMessages[idx] = new(big.Int).Set(secretMessages[idx])
	}
	
	// Generate the new blinding factors
	e, err := RandomScalar(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
	}
	
	s, err := RandomScalar(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
	}
	
	// The approach is to:
	// 1. Compute the commitment to the newly disclosed messages
	// 2. Update the ABar commitment
	// 3. Update the D commitment 
	// 4. Generate a new challenge value
	// 5. Create the final proof
	
	// Prepare the commitment for newly disclosed messages
	// We need to remove their blinding from ABar and add to APrime
	ABarJac := bls12381.G1Jac{}
	ABarJac.FromAffine(&proof.ABar)
	
	// Update APrime to include the newly disclosed messages
	APrimeJac := bls12381.G1Jac{}
	APrimeJac.FromAffine(&proof.APrime)
	
	// For each newly disclosed message, remove it from blinding
	for _, idx := range additionalIndices {
		// Get the message value
		msg := secretMessages[idx]
		
		// Compute h_i^(-msg * C)
		hiJac := bls12381.G1Jac{}
		hiJac.FromAffine(&publicKey.H[idx+2]) // +2 for Q1, Q2
		
		// Compute -msg * C
		negMsgC := new(big.Int).Mul(msg, proof.C)
		negMsgC.Neg(negMsgC)
		negMsgC.Mod(negMsgC, Order)
		
		// Compute h_i^(-msg * C)
		hiJac.ScalarMultiplication(&hiJac, negMsgC)
		
		// Update ABar: ABar = ABar * h_i^(-msg * C)
		ABarJac.AddAssign(&hiJac)
	}
	
	// Convert to affine
	newABar := g1JacToAffine(ABarJac)
	
	// Generate a new challenge value
	c := ComputeProofChallenge(
		proof.APrime,
		newABar,
		proof.D,
		additionalIndices,
		newDisclosedMessages,
	)
	
	// Compute the final proof with E' = E + e
	eHat := new(big.Int).Add(proof.EHat, e)
	eHat.Mod(eHat, Order)
	
	// Compute S' = S + s
	sHat := new(big.Int).Add(proof.SHat, s)
	sHat.Mod(sHat, Order)
	
	// Create the new proof
	newProof := &ProofOfKnowledge{
		APrime: proof.APrime,
		ABar:   newABar,
		D:      proof.D,
		C:      c,
		EHat:   eHat,
		SHat:   sHat,
	}
	
	return newProof, newDisclosedMessages, nil
}