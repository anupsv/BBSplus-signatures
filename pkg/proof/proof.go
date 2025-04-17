// Package proof provides functionality for BBS+ selective disclosure proofs.
package proof

import (
	"fmt"
	"math/big"

	"github.com/anupsv/bbsplus-signatures/pkg/core"
)

// CreateProof delegates to the implementation in the bbs package
func CreateProof(
	publicKey *core.PublicKey,
	signature *core.Signature,
	messages []*big.Int,
	disclosedIndices []int,
	header []byte,
) (*core.ProofOfKnowledge, map[int]*big.Int, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

// VerifyProof delegates to the implementation in the bbs package
func VerifyProof(
	publicKey *core.PublicKey,
	proof *core.ProofOfKnowledge,
	disclosedMessages map[int]*big.Int,
	header []byte,
) error {
	return fmt.Errorf("not implemented")
}

// BatchVerifyProofs delegates to the implementation in the bbs package
func BatchVerifyProofs(
	publicKeys []*core.PublicKey,
	proofs []*core.ProofOfKnowledge,
	disclosedMessagesList []map[int]*big.Int,
	headers [][]byte,
) error {
	return fmt.Errorf("not implemented")
}
