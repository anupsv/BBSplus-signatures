package bbs

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Errors specific to types
var (
	ErrInvalidCurvePoint = fmt.Errorf("invalid curve point")
	ErrInvalidProof      = fmt.Errorf("invalid proof")
)

// PrivateKey represents a BBS+ private key
type PrivateKey struct {
	X *big.Int // Secret scalar
}

// PublicKey represents a BBS+ public key
type PublicKey struct {
	W            bls12381.G2Affine // W = g2^x
	G2           bls12381.G2Affine // Generator of G2
	G1           bls12381.G1Affine // Generator of G1
	H            []bls12381.G1Affine // Message-specific generators
	MessageCount int             // Number of messages this key can sign
}

// KeyPair represents a BBS+ key pair
type KeyPair struct {
	PrivateKey *PrivateKey
	PublicKey  *PublicKey
}

// Signature represents a BBS+ signature
type Signature struct {
	A bls12381.G1Affine // First signature component
	E *big.Int // Random scalar
	S *big.Int // Random scalar
}

// ProofOfKnowledge represents a BBS+ proof of knowledge of a signature
type ProofOfKnowledge struct {
	APrime bls12381.G1Affine
	ABar   bls12381.G1Affine
	D      bls12381.G1Affine
	C      *big.Int
	EHat   *big.Int
	SHat   *big.Int
	MHat   map[int]*big.Int // Unrevealed messages commitments
}

// SerializeSignature converts a signature to bytes
func SerializeSignature(sig *Signature) []byte {
	var result []byte
	
	// Add A
	result = append(result, sig.A.Marshal()...)
	
	// Add E (with length prefix)
	eBytes := sig.E.Bytes()
	result = append(result, byte(len(eBytes)))
	result = append(result, eBytes...)
	
	// Add S (with length prefix)
	sBytes := sig.S.Bytes()
	result = append(result, byte(len(sBytes)))
	result = append(result, sBytes...)
	
	return result
}

// DeserializeSignature converts bytes to a signature
func DeserializeSignature(data []byte) (*Signature, error) {
	if len(data) < 50 { // Minimum size needed for a valid signature
		return nil, ErrInvalidSignatureData
	}
	
	var offset int
	
	// Parse A
	var a bls12381.G1Affine
	err := a.Unmarshal(data[offset:offset+48])
	if err != nil {
		return nil, ErrInvalidSignatureData
	}
	offset += 48
	
	// Parse E
	eLength := int(data[offset])
	offset++
	if offset+eLength > len(data) {
		return nil, ErrInvalidSignatureData
	}
	e := new(big.Int).SetBytes(data[offset:offset+eLength])
	offset += eLength
	
	// Parse S
	if offset >= len(data) {
		return nil, ErrInvalidSignatureData
	}
	sLength := int(data[offset])
	offset++
	if offset+sLength > len(data) {
		return nil, ErrInvalidSignatureData
	}
	s := new(big.Int).SetBytes(data[offset:offset+sLength])
	
	return &Signature{
		A: a,
		E: e,
		S: s,
	}, nil
}

// SerializeProof converts a proof to bytes
func SerializeProof(proof *ProofOfKnowledge) []byte {
	var result []byte
	
	// Add APrime
	result = append(result, proof.APrime.Marshal()...)
	
	// Add ABar
	result = append(result, proof.ABar.Marshal()...)
	
	// Add D
	result = append(result, proof.D.Marshal()...)
	
	// Add C (with length prefix)
	cBytes := proof.C.Bytes()
	result = append(result, byte(len(cBytes)))
	result = append(result, cBytes...)
	
	// Add EHat (with length prefix)
	eHatBytes := proof.EHat.Bytes()
	result = append(result, byte(len(eHatBytes)))
	result = append(result, eHatBytes...)
	
	// Add SHat (with length prefix)
	sHatBytes := proof.SHat.Bytes()
	result = append(result, byte(len(sHatBytes)))
	result = append(result, sHatBytes...)
	
	// Add number of undisclosed messages
	result = append(result, byte(len(proof.MHat)))
	
	// Add MHat values in sorted order by index
	indices := make([]int, 0, len(proof.MHat))
	for idx := range proof.MHat {
		indices = append(indices, idx)
	}
	
	// We'll sort indices for deterministic serialization
	for _, idx := range indices {
		mHat := proof.MHat[idx]
		
		// Add index (4 bytes, big-endian)
		idxBytes := make([]byte, 4)
		idxBytes[0] = byte(idx >> 24)
		idxBytes[1] = byte(idx >> 16)
		idxBytes[2] = byte(idx >> 8)
		idxBytes[3] = byte(idx)
		result = append(result, idxBytes...)
		
		// Add mHat value (with length prefix)
		mHatBytes := mHat.Bytes()
		result = append(result, byte(len(mHatBytes)))
		result = append(result, mHatBytes...)
	}
	
	return result
}

// DeserializeProof converts bytes to a proof
func DeserializeProof(data []byte) (*ProofOfKnowledge, error) {
	if len(data) < 150 { // Minimum size needed for a valid proof
		return nil, ErrInvalidProofData
	}
	
	var offset int
	
	// Parse APrime
	var aPrime bls12381.G1Affine
	err := aPrime.Unmarshal(data[offset:offset+48])
	if err != nil {
		return nil, ErrInvalidProofData
	}
	offset += 48
	
	// Parse ABar
	var aBar bls12381.G1Affine
	err = aBar.Unmarshal(data[offset:offset+48])
	if err != nil {
		return nil, ErrInvalidProofData
	}
	offset += 48
	
	// Parse D
	var d bls12381.G1Affine
	err = d.Unmarshal(data[offset:offset+48])
	if err != nil {
		return nil, ErrInvalidProofData
	}
	offset += 48
	
	// Parse C
	if offset >= len(data) {
		return nil, ErrInvalidProofData
	}
	cLength := int(data[offset])
	offset++
	if offset+cLength > len(data) {
		return nil, ErrInvalidProofData
	}
	c := new(big.Int).SetBytes(data[offset:offset+cLength])
	offset += cLength
	
	// Parse EHat
	if offset >= len(data) {
		return nil, ErrInvalidProofData
	}
	eHatLength := int(data[offset])
	offset++
	if offset+eHatLength > len(data) {
		return nil, ErrInvalidProofData
	}
	eHat := new(big.Int).SetBytes(data[offset:offset+eHatLength])
	offset += eHatLength
	
	// Parse SHat
	if offset >= len(data) {
		return nil, ErrInvalidProofData
	}
	sHatLength := int(data[offset])
	offset++
	if offset+sHatLength > len(data) {
		return nil, ErrInvalidProofData
	}
	sHat := new(big.Int).SetBytes(data[offset:offset+sHatLength])
	offset += sHatLength
	
	// Parse number of undisclosed messages
	if offset >= len(data) {
		return nil, ErrInvalidProofData
	}
	mHatCount := int(data[offset])
	offset++
	
	// Parse MHat values
	mHat := make(map[int]*big.Int, mHatCount)
	for i := 0; i < mHatCount; i++ {
		if offset+4 > len(data) {
			return nil, ErrInvalidProofData
		}
		
		// Parse index
		idx := int(data[offset])<<24 | int(data[offset+1])<<16 | 
		      int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4
		
		// Parse mHat value
		if offset >= len(data) {
			return nil, ErrInvalidProofData
		}
		mHatLength := int(data[offset])
		offset++
		if offset+mHatLength > len(data) {
			return nil, ErrInvalidProofData
		}
		mHatValue := new(big.Int).SetBytes(data[offset:offset+mHatLength])
		offset += mHatLength
		
		mHat[idx] = mHatValue
	}
	
	return &ProofOfKnowledge{
		APrime: aPrime,
		ABar:   aBar,
		D:      d,
		C:      c,
		EHat:   eHat,
		SHat:   sHat,
		MHat:   mHat,
	}, nil
}