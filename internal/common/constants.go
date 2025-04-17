package common

import (
	"math/big"
)

// BLS12-381 curve constants
var (
	// Order is the order of the BLS12-381 curve
	Order = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	
	// SubgroupOrder is the order of the r-order subgroup
	SubgroupOrder = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	
	// FieldSize is the size of the field
	FieldSize = new(big.Int).SetString("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
)

// Domain separation tags
const (
	// DST_G1 is the domain separation tag for hashing to G1
	DST_G1 = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
	
	// DST_G2 is the domain separation tag for hashing to G2
	DST_G2 = "BBS_BLS12381G2_XMD:SHA-256_SSWU_RO_"
	
	// DST_PROOF is the domain separation tag for generating proof challenges
	DST_PROOF = "BBS_BLS12381_XOF:SHAKE-256_PROOF_"
	
	// DST_SIG is the domain separation tag for signature generation
	DST_SIG = "BBS_BLS12381_XOF:SHAKE-256_SIG_"
)