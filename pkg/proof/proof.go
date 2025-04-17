package proof

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"

	"github.com/asv/projects/bbs/pkg/core"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Builder is used to construct a BBS+ selective disclosure proof
type Builder struct {
	publicKey        *core.PublicKey
	signature        *core.Signature
	messages         []*big.Int
	disclosedIndices []int
	header           []byte
	predicates       map[int]Predicate
	options          *core.ProofOptions
}

// Predicate represents a ZK predicate for proof creation
type Predicate struct {
	Type   PredicateType
	Value  *big.Int   // For equals, greater than, less than, not equal
	Values []*big.Int // For range (min, max)
}

// NewBuilder creates a new proof builder
func NewBuilder() *Builder {
	return &Builder{
		disclosedIndices: make([]int, 0),
		predicates:       make(map[int]Predicate),
		options:          &core.ProofOptions{},
	}
}

// SetPublicKey sets the public key for proof creation
func (b *Builder) SetPublicKey(pk *core.PublicKey) *Builder {
	b.publicKey = pk
	return b
}

// SetSignature sets the signature for proof creation
func (b *Builder) SetSignature(sig *core.Signature) *Builder {
	b.signature = sig
	return b
}

// SetMessages sets the messages for proof creation
func (b *Builder) SetMessages(messages []*big.Int) *Builder {
	b.messages = messages
	return b
}

// SetHeader sets the header data for domain separation
func (b *Builder) SetHeader(header []byte) *Builder {
	b.header = header
	return b
}

// SetOptions sets the proof creation options
func (b *Builder) SetOptions(options *core.ProofOptions) *Builder {
	b.options = options
	return b
}

// Disclose adds the given indices to the list of messages to disclose
func (b *Builder) Disclose(indices ...int) *Builder {
	for _, idx := range indices {
		// Check if index is already in the list
		found := false
		for _, existingIdx := range b.disclosedIndices {
			if existingIdx == idx {
				found = true
				break
			}
		}
		if !found {
			b.disclosedIndices = append(b.disclosedIndices, idx)
		}
	}
	return b
}

// AddPredicate adds a predicate for a specific message
func (b *Builder) AddPredicate(messageIndex int, predType PredicateType, values ...*big.Int) *Builder {
	switch predType {
	case PredicateEquals, PredicateGreaterThan, PredicateLessThan, PredicateNotEqual:
		if len(values) != 1 {
			// Log error but don't halt execution
			fmt.Printf("Error: Predicate requires exactly 1 value, got %d\n", len(values))
			return b
		}
		b.predicates[messageIndex] = Predicate{
			Type:  predType,
			Value: values[0],
		}
	case PredicateInRange:
		if len(values) != 2 {
			// Log error but don't halt execution
			fmt.Printf("Error: Range predicate requires exactly 2 values, got %d\n", len(values))
			return b
		}
		b.predicates[messageIndex] = Predicate{
			Type:   predType,
			Values: values,
		}
	default:
		// Log error for unknown predicate type
		fmt.Printf("Error: Unknown predicate type: %d\n", predType)
	}
	return b
}

// Build creates the proof using the configured parameters
func (b *Builder) Build() (*core.ProofOfKnowledge, map[int]*big.Int, error) {
	// Validate the inputs
	if b.publicKey == nil {
		return nil, nil, fmt.Errorf("public key is required")
	}
	
	if b.signature == nil {
		return nil, nil, fmt.Errorf("signature is required")
	}
	
	if len(b.messages) == 0 {
		return nil, nil, fmt.Errorf("messages are required")
	}
	
	if len(b.messages) != b.publicKey.MessageCount {
		return nil, nil, fmt.Errorf("message count mismatch: expected %d, got %d", 
			b.publicKey.MessageCount, len(b.messages))
	}

	// Force reveal all messages if the option is set
	if b.options != nil && b.options.RevealAll {
		b.disclosedIndices = make([]int, len(b.messages))
		for i := range b.messages {
			b.disclosedIndices[i] = i
		}
	}
	
	// Create a map for faster lookup of disclosed indices
	disclosedMap := make(map[int]bool)
	for _, idx := range b.disclosedIndices {
		disclosedMap[idx] = true
	}
	
	// Create a map of disclosed messages
	disclosedMessages := make(map[int]*big.Int)
	for _, idx := range b.disclosedIndices {
		if idx < 0 || idx >= len(b.messages) {
			return nil, nil, fmt.Errorf("invalid disclosed index: %d", idx)
		}
		disclosedMessages[idx] = b.messages[idx]
	}
	
	// Calculate domain
	var domain *big.Int
	if b.header != nil {
		// Call domain calculation function from core package
		// This will need to be implemented in core package
		domain = calculateDomain(b.publicKey, b.header)
	} else {
		// Use default domain if no header is provided
		domain = new(big.Int).SetInt64(1)
	}

	// Generate randomness r for signature blinding
	var r *big.Int
	var err error
	
	if b.options != nil && b.options.DeterministicProof {
		// Use deterministic r for testing
		r = new(big.Int).SetInt64(42)
	} else {
		// Generate cryptographically secure random r
		r, err = randomScalar(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate random value: %w", err)
		}
	}

	// Compute A' = A * g1^r
	APrimeJac := bls12381.G1Jac{}
	APrimeJac.FromAffine(&b.signature.A)
	
	g1rJac := bls12381.G1Jac{}
	g1rJac.FromAffine(&b.publicKey.G1)
	g1rJac.ScalarMultiplication(&g1rJac, r)
	APrimeJac.AddAssign(&g1rJac)
	
	// Convert to affine
	APrime := g1JacToAffine(APrimeJac)
	
	// Compute A-bar
	// Initialize A-bar with A'
	ABarJac := bls12381.G1Jac{}
	ABarJac.FromAffine(&APrime)
	
	// Compute blinded messages contribution to A-bar
	for i := 0; i < len(b.messages); i++ {
		if disclosedMap[i] {
			continue // Skip disclosed messages
		}
		
		// Compute h_i^{m_i * r} for hidden messages
		msg := b.messages[i]
		mr := new(big.Int).Mul(msg, r)
		mr.Mod(mr, getOrder())
		
		himrJac := bls12381.G1Jac{}
		// The actual index in H depends on the core package's convention
		// Assuming H[0] is H0, H[1] is Q1, H[2] is Q2, and H[i+2] is for message i
		himrJac.FromAffine(&b.publicKey.H[i+2]) 
		himrJac.ScalarMultiplication(&himrJac, mr)
		ABarJac.AddAssign(&himrJac)
	}
	
	// Convert to affine
	ABar := g1JacToAffine(ABarJac)

	// Generate random blinding factors
	var eBlind, sBlind, domainBlind *big.Int
	if b.options != nil && b.options.DeterministicProof {
		// Use deterministic values for testing
		eBlind = new(big.Int).SetInt64(123)
		sBlind = new(big.Int).SetInt64(456)
		domainBlind = new(big.Int).SetInt64(789)
	} else {
		eBlind, err = randomScalar(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
		}
		
		sBlind, err = randomScalar(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
		}
		
		domainBlind, err = randomScalar(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate domain blinding: %w", err)
		}
	}

	// Create blinding factors for undisclosed messages
	mBlind := make(map[int]*big.Int)
	for i := 0; i < len(b.messages); i++ {
		if !disclosedMap[i] {
			if b.options != nil && b.options.DeterministicProof {
				// Use deterministic values for testing
				mBlind[i] = new(big.Int).SetInt64(int64(1000 + i))
			} else {
				mBlind[i], err = randomScalar(rand.Reader)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to generate blinding: %w", err)
				}
			}
		}
	}

	// Compute commitment D
	// Start with H0^sBlind (or Q1^sBlind in the current convention)
	DJac := bls12381.G1Jac{}
	q1sBlindJac := bls12381.G1Jac{}
	q1sBlindJac.FromAffine(&b.publicKey.H[0])
	q1sBlindJac.ScalarMultiplication(&q1sBlindJac, sBlind)
	DJac.AddAssign(&q1sBlindJac)
	
	// Add Q2^domainBlind
	q2dBlindJac := bls12381.G1Jac{}
	q2dBlindJac.FromAffine(&b.publicKey.H[1])
	q2dBlindJac.ScalarMultiplication(&q2dBlindJac, domainBlind)
	DJac.AddAssign(&q2dBlindJac)
	
	// Add H_i^mBlind_i for each undisclosed message
	for i := 0; i < len(b.messages); i++ {
		if !disclosedMap[i] {
			hiJac := bls12381.G1Jac{}
			hiJac.FromAffine(&b.publicKey.H[i+2]) // +2 for first two positions
			hiJac.ScalarMultiplication(&hiJac, mBlind[i])
			DJac.AddAssign(&hiJac)
		}
	}
	
	// Convert to affine
	D := g1JacToAffine(DJac)

	// Compute the Fiat-Shamir challenge c
	disclosedIndices := make([]int, 0, len(disclosedMessages))
	for idx := range disclosedMessages {
		disclosedIndices = append(disclosedIndices, idx)
	}
	
	// Sort indices for deterministic challenge computation
	sort.Ints(disclosedIndices)
	
	c := computeProofChallenge(APrime, ABar, D, disclosedIndices, disclosedMessages)

	// Compute e^ = e*c + eBlind
	eHat := new(big.Int).Mul(b.signature.E, c)
	eHat.Add(eHat, eBlind)
	eHat.Mod(eHat, getOrder())
	
	// Compute s^ = s*c + sBlind
	sHat := new(big.Int).Mul(b.signature.S, c)
	sHat.Add(sHat, sBlind)
	sHat.Mod(sHat, getOrder())
	
	// Compute m_i^ = m_i*c + mBlind_i for each undisclosed message
	// Convert to appropriate structure for ProofOfKnowledge
	undisclosedIndices := make([]int, 0)
	for i := 0; i < len(b.messages); i++ {
		if !disclosedMap[i] {
			undisclosedIndices = append(undisclosedIndices, i)
		}
	}
	
	// Sort for deterministic ordering
	sort.Ints(undisclosedIndices)
	
	mHatValues := make([]*big.Int, len(undisclosedIndices))
	
	for i, idx := range undisclosedIndices {
		mHatValues[i] = new(big.Int).Mul(b.messages[idx], c)
		mHatValues[i].Add(mHatValues[i], mBlind[idx])
		mHatValues[i].Mod(mHatValues[i], getOrder())
	}

	// Create the final proof
	proof := &core.ProofOfKnowledge{
		APrime: APrime,
		ABar:   ABar,
		D:      D,
		C:      c,
		EHat:   eHat,
		SHat:   sHat,
		MHat:   mHatValues,
		// RHat left empty as it's not needed for basic proofs
	}
	
	return proof, disclosedMessages, nil
}

// Verifier is used to verify a BBS+ selective disclosure proof
type Verifier struct {
	publicKey         *core.PublicKey
	proof             *core.ProofOfKnowledge
	disclosedMessages map[int]*big.Int
	header            []byte
	options           *core.VerifyOptions
}

// NewVerifier creates a new proof verifier
func NewVerifier() *Verifier {
	return &Verifier{
		options: &core.VerifyOptions{},
	}
}

// SetPublicKey sets the public key for verification
func (v *Verifier) SetPublicKey(pk *core.PublicKey) *Verifier {
	v.publicKey = pk
	return v
}

// SetProof sets the proof to verify
func (v *Verifier) SetProof(proof *core.ProofOfKnowledge) *Verifier {
	v.proof = proof
	return v
}

// SetDisclosedMessages sets the disclosed messages for verification
func (v *Verifier) SetDisclosedMessages(messages map[int]*big.Int) *Verifier {
	v.disclosedMessages = messages
	return v
}

// SetHeader sets the header data used for domain separation
func (v *Verifier) SetHeader(header []byte) *Verifier {
	v.header = header
	return v
}

// SetOptions sets the verification options
func (v *Verifier) SetOptions(options *core.VerifyOptions) *Verifier {
	v.options = options
	return v
}

// Verify checks the validity of the proof
func (v *Verifier) Verify() error {
	// Validate inputs
	if v.publicKey == nil {
		return fmt.Errorf("public key is required")
	}
	
	if v.proof == nil {
		return fmt.Errorf("proof is required")
	}
	
	// Validate message indices
	for idx := range v.disclosedMessages {
		if idx < 0 || idx >= v.publicKey.MessageCount {
			return fmt.Errorf("invalid disclosed message index: %d", idx)
		}
	}
	
	// Get the indices for disclosed messages
	disclosedIndices := make([]int, 0, len(v.disclosedMessages))
	for idx := range v.disclosedMessages {
		disclosedIndices = append(disclosedIndices, idx)
	}
	
	// Sort indices for deterministic challenge computation
	sort.Ints(disclosedIndices)
	
	// Recompute the challenge
	c := computeProofChallenge(v.proof.APrime, v.proof.ABar, v.proof.D, disclosedIndices, v.disclosedMessages)
	
	// Check if the computed challenge matches the one in the proof
	if c.Cmp(v.proof.C) != 0 {
		return fmt.Errorf("invalid proof: challenge verification failed")
	}
	
	// Calculate domain value
	var domain *big.Int
	if v.header != nil {
		domain = calculateDomain(v.publicKey, v.header)
	} else {
		domain = new(big.Int).SetInt64(1)
	}
	
	// Prepare points and scalars for multi-scalar multiplication
	// We need to compute: g1b = P1 + Q1*S^ + Q2*domain + ∑(H_i*m_i) - D*c
	
	// This is used for e(B, P2) = e(A', W)*e(A', P2)^e^
	// Start with P1 (g1)
	points := []bls12381.G1Affine{v.publicKey.G1}
	scalars := []*big.Int{big.NewInt(1)}
	
	// Add Q1*S^
	points = append(points, v.publicKey.H[0])
	scalars = append(scalars, v.proof.SHat)
	
	// Add Q2*domain
	points = append(points, v.publicKey.H[1])
	scalars = append(scalars, domain)
	
	// Add each H_i*m_i for disclosed messages
	for idx, msg := range v.disclosedMessages {
		// For disclosed messages, use the disclosed value directly
		points = append(points, v.publicKey.H[idx+2]) // +2 for Q1, Q2
		scalars = append(scalars, msg)
	}
	
	// Add each H_i*m_i^ for undisclosed messages
	// Assuming MHat in the proof contains the values in the same order 
	// as the sorted undisclosed indices
	undisclosedIndices := make([]int, 0)
	for i := 0; i < v.publicKey.MessageCount; i++ {
		if _, disclosed := v.disclosedMessages[i]; !disclosed {
			undisclosedIndices = append(undisclosedIndices, i)
		}
	}
	
	// Sort for deterministic ordering
	sort.Ints(undisclosedIndices)
	
	// Match undisclosed indices with MHat values
	for i, idx := range undisclosedIndices {
		if i < len(v.proof.MHat) {
			points = append(points, v.publicKey.H[idx+2]) // +2 for Q1, Q2
			scalars = append(scalars, v.proof.MHat[i])
		}
	}
	
	// Subtract D*c (add D*(-c))
	points = append(points, v.proof.D)
	negC := new(big.Int).Neg(v.proof.C)
	negC.Mod(negC, getOrder())
	scalars = append(scalars, negC)
	
	// Perform multi-scalar multiplication
	g1bJac, err := multiScalarMulG1(points, scalars)
	if err != nil {
		return fmt.Errorf("failed multi-scalar multiplication: %w", err)
	}
	
	// Convert to affine
	g1b := g1JacToAffine(g1bJac)
	
	// Now compute T = ABar^c * D using multi-scalar multiplication
	TPoints := []bls12381.G1Affine{v.proof.ABar, v.proof.D}
	
	// Create scalars (C and 1)
	one := big.NewInt(1)
	TScalars := []*big.Int{v.proof.C, one}
	
	// Perform multi-scalar multiplication
	TJac, err := multiScalarMulG1(TPoints, TScalars)
	if err != nil {
		return fmt.Errorf("failed multi-scalar multiplication: %w", err)
	}
	
	// Convert to affine
	T := g1JacToAffine(TJac)
	
	// Negate g2 for the second pairing
	negG2Jac := bls12381.G2Jac{}
	negG2Jac.FromAffine(&v.publicKey.G2)
	negG2Jac.Neg(&negG2Jac)
	negG2 := g2JacToAffine(negG2Jac)
	
	// Check pairing equation: e(APrime, W) * e(g1b, -g2) * e(T, g2) = 1
	pairingResult, err := bls12381.Pair(
		[]bls12381.G1Affine{v.proof.APrime, g1b, T},
		[]bls12381.G2Affine{v.publicKey.W, negG2, v.publicKey.G2},
	)
	if err != nil {
		return fmt.Errorf("pairing computation failed: %w", err)
	}
	
	// Check if the pairing result is 1
	if !pairingResult.IsOne() {
		return fmt.Errorf("invalid proof: pairing check failed")
	}
	
	return nil
}

// BatchVerifier verifies multiple proofs in a single batch operation
type BatchVerifier struct {
	publicKeys         []*core.PublicKey
	proofs             []*core.ProofOfKnowledge
	disclosedMessages  []map[int]*big.Int
	headers            [][]byte
	options            *core.VerifyOptions
}

// NewBatchVerifier creates a new batch proof verifier
func NewBatchVerifier() *BatchVerifier {
	return &BatchVerifier{
		publicKeys:        make([]*core.PublicKey, 0),
		proofs:            make([]*core.ProofOfKnowledge, 0),
		disclosedMessages: make([]map[int]*big.Int, 0),
		headers:           make([][]byte, 0),
		options:           &core.VerifyOptions{Batch: true},
	}
}

// Add adds a proof to the batch for verification
func (bv *BatchVerifier) Add(
	publicKey *core.PublicKey, 
	proof *core.ProofOfKnowledge, 
	disclosedMessages map[int]*big.Int, 
	header []byte,
) *BatchVerifier {
	bv.publicKeys = append(bv.publicKeys, publicKey)
	bv.proofs = append(bv.proofs, proof)
	bv.disclosedMessages = append(bv.disclosedMessages, disclosedMessages)
	bv.headers = append(bv.headers, header)
	return bv
}

// SetOptions sets the verification options
func (bv *BatchVerifier) SetOptions(options *core.VerifyOptions) *BatchVerifier {
	bv.options = options
	return bv
}

// Verify performs batch verification of all added proofs
func (bv *BatchVerifier) Verify() error {
	// Validate inputs
	if len(bv.publicKeys) == 0 {
		return nil // No proofs to verify
	}
	
	if len(bv.publicKeys) != len(bv.proofs) || len(bv.proofs) != len(bv.disclosedMessages) {
		return fmt.Errorf("mismatched array lengths in batch verification")
	}
	
	// If there's only one proof, use the regular verification
	if len(bv.proofs) == 1 {
		verifier := NewVerifier()
		verifier.SetPublicKey(bv.publicKeys[0])
		verifier.SetProof(bv.proofs[0])
		verifier.SetDisclosedMessages(bv.disclosedMessages[0])
		if len(bv.headers) > 0 {
			verifier.SetHeader(bv.headers[0])
		}
		verifier.SetOptions(bv.options)
		return verifier.Verify()
	}
	
	// First, verify all challenges independently
	for i, proof := range bv.proofs {
		// Get the indices for disclosed messages
		disclosedIndices := make([]int, 0, len(bv.disclosedMessages[i]))
		for idx := range bv.disclosedMessages[i] {
			disclosedIndices = append(disclosedIndices, idx)
		}
		
		// Sort indices for deterministic challenge computation
		sort.Ints(disclosedIndices)
		
		// Compute the challenge
		c := computeProofChallenge(
			proof.APrime, 
			proof.ABar, 
			proof.D, 
			disclosedIndices, 
			bv.disclosedMessages[i],
		)
		
		// Check if the computed challenge matches the one in the proof
		if c.Cmp(proof.C) != 0 {
			return fmt.Errorf("challenge verification failed for proof %d", i)
		}
	}
	
	// Generate random scalars for batch verification using constant-time operations
	batchScalars := make([]*big.Int, len(bv.proofs))
	
	// Generate cryptographically strong random scalars
	for i := range batchScalars {
		var err error
		batchScalars[i], err = randomScalar(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate batch scalars: %w", err)
		}
	}
	
	// Prepare points for the final pairing check
	pointCapacity := len(bv.proofs) * 3 // Each proof contributes approximately 3 points
	g1Points := make([]bls12381.G1Affine, 0, pointCapacity)
	g2Points := make([]bls12381.G2Affine, 0, pointCapacity)
	
	// Process each proof
	for i, proof := range bv.proofs {
		publicKey := bv.publicKeys[i]
		disclosedMessages := bv.disclosedMessages[i]
		
		// Get the domain value
		var domain *big.Int
		if i < len(bv.headers) && bv.headers[i] != nil {
			domain = calculateDomain(publicKey, bv.headers[i])
		} else {
			domain = new(big.Int).SetInt64(1)
		}
		
		// Multiply by batch scalar for this proof
		batchScalar := batchScalars[i]
		
		// Compute the g1b point as in single verification
		// Prepare arrays for multi-scalar multiplication
		pointsCount := 3 + len(disclosedMessages) + len(proof.MHat) + 1
		points := make([]bls12381.G1Affine, 0, pointsCount)
		scalars := make([]*big.Int, 0, pointsCount)
		
		// Start with P1 * batchScalar
		points = append(points, publicKey.G1)
		batchScalarCopy := new(big.Int).Set(batchScalar)
		scalars = append(scalars, batchScalarCopy)
		
		// Add Q1*S^ * batchScalar
		points = append(points, publicKey.H[0])
		sHatBatch := new(big.Int).Mul(proof.SHat, batchScalar)
		sHatBatch.Mod(sHatBatch, getOrder())
		scalars = append(scalars, sHatBatch)
		
		// Add Q2*domain * batchScalar
		points = append(points, publicKey.H[1])
		domainBatch := new(big.Int).Mul(domain, batchScalar)
		domainBatch.Mod(domainBatch, getOrder())
		scalars = append(scalars, domainBatch)
		
		// Add each H_i*m_i for disclosed messages
		for idx, msg := range disclosedMessages {
			points = append(points, publicKey.H[idx+2]) // +2 for Q1, Q2
			
			// Compute batchScalar * msg
			msgBatch := new(big.Int).Mul(msg, batchScalar)
			msgBatch.Mod(msgBatch, getOrder())
			scalars = append(scalars, msgBatch)
		}
		
		// Add each H_i*m_i^ for undisclosed messages
		// Get undisclosed indices
		undisclosedIndices := make([]int, 0)
		for j := 0; j < publicKey.MessageCount; j++ {
			if _, disclosed := disclosedMessages[j]; !disclosed {
				undisclosedIndices = append(undisclosedIndices, j)
			}
		}
		
		// Sort for deterministic ordering
		sort.Ints(undisclosedIndices)
		
		// Match undisclosed indices with MHat values
		for j, idx := range undisclosedIndices {
			if j < len(proof.MHat) {
				points = append(points, publicKey.H[idx+2]) // +2 for Q1, Q2
				
				// Compute batchScalar * mHat[j]
				mHatBatch := new(big.Int).Mul(proof.MHat[j], batchScalar)
				mHatBatch.Mod(mHatBatch, getOrder())
				scalars = append(scalars, mHatBatch)
			}
		}
		
		// Subtract D*c * batchScalar (add D*(-c * batchScalar))
		points = append(points, proof.D)
		negC := new(big.Int).Neg(proof.C)
		negC.Mod(negC, getOrder())
		negCBatch := new(big.Int).Mul(negC, batchScalar)
		negCBatch.Mod(negCBatch, getOrder())
		scalars = append(scalars, negCBatch)
		
		// Perform multi-scalar multiplication
		g1bJac, err := multiScalarMulG1(points, scalars)
		if err != nil {
			return fmt.Errorf("failed multi-scalar multiplication: %w", err)
		}
		
		// Convert to affine
		g1b := g1JacToAffine(g1bJac)
		
		// Add e(g1b, -g2) to the pairing check
		negG2Jac := bls12381.G2Jac{}
		negG2Jac.FromAffine(&publicKey.G2)
		negG2Jac.Neg(&negG2Jac)
		negG2 := g2JacToAffine(negG2Jac)
		
		g1Points = append(g1Points, g1b)
		g2Points = append(g2Points, negG2)
		
		// Compute T = ABar^c * D using multi-scalar multiplication
		TPoints := []bls12381.G1Affine{proof.ABar, proof.D}
		
		// Create scalars (C*batchScalar and batchScalar)
		cBatch := new(big.Int).Mul(proof.C, batchScalar)
		cBatch.Mod(cBatch, getOrder())
		batchScalarCopy = new(big.Int).Set(batchScalar)
		
		TScalars := []*big.Int{cBatch, batchScalarCopy}
		
		// Perform multi-scalar multiplication
		TJac, err := multiScalarMulG1(TPoints, TScalars)
		if err != nil {
			return fmt.Errorf("failed multi-scalar multiplication: %w", err)
		}
		
		// Convert to affine
		T := g1JacToAffine(TJac)
		
		// Add e(T, g2) to the pairing check
		g1Points = append(g1Points, T)
		g2Points = append(g2Points, publicKey.G2)
		
		// Add e(APrime, W) to the pairing check
		g1Points = append(g1Points, proof.APrime)
		g2Points = append(g2Points, publicKey.W)
	}
	
	// Perform the batch pairing check
	pairingResult, err := bls12381.Pair(g1Points, g2Points)
	if err != nil {
		return fmt.Errorf("pairing computation failed: %w", err)
	}
	
	// Check if the pairing result is 1
	if !pairingResult.IsOne() {
		return fmt.Errorf("batch verification failed: invalid signature")
	}
	
	return nil
}

// Helper functions

// g1JacToAffine converts a G1 Jacobian point to affine coordinates
func g1JacToAffine(p bls12381.G1Jac) bls12381.G1Affine {
	result := bls12381.G1Affine{}
	result.FromJacobian(&p)
	return result
}

// g2JacToAffine converts a G2 Jacobian point to affine coordinates
func g2JacToAffine(p bls12381.G2Jac) bls12381.G2Affine {
	result := bls12381.G2Affine{}
	result.FromJacobian(&p)
	return result
}

// getOrder returns the order of the curve's scalar field
func getOrder() *big.Int {
	// BLS12-381 scalar field order
	// r = 73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
	return bls12381.Order
}

// randomScalar generates a random scalar in the range [0, order-1]
func randomScalar(reader rand.Reader) (*big.Int, error) {
	order := getOrder()
	bytes := make([]byte, 32) // 256 bits should be enough
	
	_, err := reader.Read(bytes)
	if err != nil {
		return nil, err
	}
	
	scalar := new(big.Int).SetBytes(bytes)
	scalar.Mod(scalar, order)
	
	return scalar, nil
}

// multiScalarMulG1 performs multi-scalar multiplication for G1 points
func multiScalarMulG1(points []bls12381.G1Affine, scalars []*big.Int) (bls12381.G1Jac, error) {
	if len(points) != len(scalars) {
		return bls12381.G1Jac{}, fmt.Errorf("number of points and scalars must match")
	}
	
	// Use gnark-crypto's MultiExp functionality
	result := bls12381.G1Jac{}
	result.MultiExp(points, scalars, 1)
	
	return result, nil
}

// computeProofChallenge computes the Fiat-Shamir challenge for the proof
func computeProofChallenge(
	APrime bls12381.G1Affine,
	ABar bls12381.G1Affine,
	D bls12381.G1Affine,
	disclosedIndices []int,
	disclosedMessages map[int]*big.Int,
) *big.Int {
	// Implementation depends on the core package's hash function
	// This is a simplified version - in practice use a stronger hash construction
	
	// Create hash input: APrime || ABar || D || disclosed_messages
	// For each disclosed message: index || message
	
	// Convert each component to bytes
	apBytes := APrime.Marshal()
	abBytes := ABar.Marshal()
	dBytes := D.Marshal()
	
	// Concatenate everything
	data := append(apBytes, abBytes...)
	data = append(data, dBytes...)
	
	// Add disclosed indices and messages in sorted order
	for _, idx := range disclosedIndices {
		// Add index as 4 bytes (big-endian)
		idxBytes := make([]byte, 4)
		idxBytes[0] = byte(idx >> 24)
		idxBytes[1] = byte(idx >> 16)
		idxBytes[2] = byte(idx >> 8)
		idxBytes[3] = byte(idx)
		data = append(data, idxBytes...)
		
		// Add message value (big-endian)
		msg := disclosedMessages[idx]
		msgBytes := msg.Bytes()
		data = append(data, msgBytes...)
	}
	
	// Hash the data - usually using SHA-256 or similar
	// For simplicity, just mod the data by the order
	// In practice, use a cryptographic hash function
	hasher := bls12381.NewHash()
	hasher.Write(data)
	hashBytes := hasher.Sum(nil)
	
	// Convert to big.Int and mod by order
	challenge := new(big.Int).SetBytes(hashBytes)
	challenge.Mod(challenge, getOrder())
	
	return challenge
}

// calculateDomain computes a domain separation value
func calculateDomain(publicKey *core.PublicKey, header []byte) *big.Int {
	// Simple domain calculation - hash the public key and header
	if header == nil {
		return new(big.Int).SetInt64(1)
	}
	
	// Hash the header and public key data
	hasher := bls12381.NewHash()
	
	// Add public key data
	pkBytes := publicKey.W.Marshal()
	hasher.Write(pkBytes)
	
	// Add header data
	hasher.Write(header)
	
	// Get hash result
	hashBytes := hasher.Sum(nil)
	
	// Convert to big.Int and mod by order
	domain := new(big.Int).SetBytes(hashBytes)
	domain.Mod(domain, getOrder())
	
	return domain
}