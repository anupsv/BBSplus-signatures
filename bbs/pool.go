package bbs

import (
	"math/big"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// ObjectPool provides a memory pool for frequently used cryptographic objects
// to reduce memory allocations and improve performance
type ObjectPool struct {
	// Big integer pools
	bigIntPool       sync.Pool
	bigIntSlicePool  sync.Pool

	// BLS12-381 point pools
	g1JacPool        sync.Pool
	g1AffinePool     sync.Pool
	g1AffineSlicePool sync.Pool
	g2JacPool        sync.Pool
	g2AffinePool     sync.Pool
	g2AffineSlicePool sync.Pool

	// Scalars pool
	scalarSlicePool  sync.Pool
	
	// Specialized pools for proof operations
	disclosedMsgPool sync.Pool      // map[int]*big.Int
	pointIndexPool   sync.Pool      // map[int]bls12381.G1Affine
	challengePool    sync.Pool      // for challenge data
	msgBatchPool     sync.Pool      // for batch message operations
}

// NewObjectPool creates a new object pool
func NewObjectPool() *ObjectPool {
	pool := &ObjectPool{
		bigIntPool: sync.Pool{
			New: func() interface{} {
				return new(big.Int)
			},
		},
		bigIntSlicePool: sync.Pool{
			New: func() interface{} {
				return make([]*big.Int, 0, 8) // Default capacity
			},
		},
		g1JacPool: sync.Pool{
			New: func() interface{} {
				return new(bls12381.G1Jac)
			},
		},
		g1AffinePool: sync.Pool{
			New: func() interface{} {
				return new(bls12381.G1Affine)
			},
		},
		g1AffineSlicePool: sync.Pool{
			New: func() interface{} {
				return make([]bls12381.G1Affine, 0, 8)
			},
		},
		g2JacPool: sync.Pool{
			New: func() interface{} {
				return new(bls12381.G2Jac)
			},
		},
		g2AffinePool: sync.Pool{
			New: func() interface{} {
				return new(bls12381.G2Affine)
			},
		},
		g2AffineSlicePool: sync.Pool{
			New: func() interface{} {
				return make([]bls12381.G2Affine, 0, 8)
			},
		},
		scalarSlicePool: sync.Pool{
			New: func() interface{} {
				return make([]*big.Int, 0, 8)
			},
		},
		// Initialize specialized pools
		disclosedMsgPool: sync.Pool{
			New: func() interface{} {
				return make(map[int]*big.Int)
			},
		},
		pointIndexPool: sync.Pool{
			New: func() interface{} {
				return make(map[int]bls12381.G1Affine)
			},
		},
		challengePool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, 1024) // Typical buffer for challenge data
			},
		},
		msgBatchPool: sync.Pool{
			New: func() interface{} {
				return make(map[int][]byte, 8) // For batch operations
			},
		},
	}
	return pool
}

// Singleton instance of the object pool
var defaultPool = NewObjectPool()

// GetBigInt gets a big.Int from the pool
func (p *ObjectPool) GetBigInt() *big.Int {
	return p.bigIntPool.Get().(*big.Int).SetInt64(0)
}

// PutBigInt returns a big.Int to the pool
func (p *ObjectPool) PutBigInt(i *big.Int) {
	if i != nil {
		p.bigIntPool.Put(i)
	}
}

// GetBigIntSlice gets a slice of big.Int pointers from the pool
func (p *ObjectPool) GetBigIntSlice(capacity int) []*big.Int {
	slice := p.bigIntSlicePool.Get().([]*big.Int)
	if cap(slice) < capacity {
		// If capacity is too small, create a new slice
		return make([]*big.Int, 0, capacity)
	}
	return slice[:0] // Reset length to 0 but keep capacity
}

// PutBigIntSlice returns a slice of big.Int pointers to the pool
func (p *ObjectPool) PutBigIntSlice(slice []*big.Int) {
	if slice != nil {
		p.bigIntSlicePool.Put(slice)
	}
}

// GetG1Jac gets a G1 Jacobian point from the pool
func (p *ObjectPool) GetG1Jac() *bls12381.G1Jac {
	return p.g1JacPool.Get().(*bls12381.G1Jac)
}

// PutG1Jac returns a G1 Jacobian point to the pool
func (p *ObjectPool) PutG1Jac(g *bls12381.G1Jac) {
	if g != nil {
		p.g1JacPool.Put(g)
	}
}

// GetG1Affine gets a G1 Affine point from the pool
func (p *ObjectPool) GetG1Affine() *bls12381.G1Affine {
	return p.g1AffinePool.Get().(*bls12381.G1Affine)
}

// PutG1Affine returns a G1 Affine point to the pool
func (p *ObjectPool) PutG1Affine(g *bls12381.G1Affine) {
	if g != nil {
		p.g1AffinePool.Put(g)
	}
}

// GetG1AffineSlice gets a slice of G1 Affine points from the pool
func (p *ObjectPool) GetG1AffineSlice(capacity int) []bls12381.G1Affine {
	slice := p.g1AffineSlicePool.Get().([]bls12381.G1Affine)
	if cap(slice) < capacity {
		return make([]bls12381.G1Affine, 0, capacity)
	}
	return slice[:0]
}

// PutG1AffineSlice returns a slice of G1 Affine points to the pool
func (p *ObjectPool) PutG1AffineSlice(slice []bls12381.G1Affine) {
	if slice != nil {
		p.g1AffineSlicePool.Put(slice)
	}
}

// GetG2Jac gets a G2 Jacobian point from the pool
func (p *ObjectPool) GetG2Jac() *bls12381.G2Jac {
	return p.g2JacPool.Get().(*bls12381.G2Jac)
}

// PutG2Jac returns a G2 Jacobian point to the pool
func (p *ObjectPool) PutG2Jac(g *bls12381.G2Jac) {
	if g != nil {
		p.g2JacPool.Put(g)
	}
}

// GetG2Affine gets a G2 Affine point from the pool
func (p *ObjectPool) GetG2Affine() *bls12381.G2Affine {
	return p.g2AffinePool.Get().(*bls12381.G2Affine)
}

// PutG2Affine returns a G2 Affine point to the pool
func (p *ObjectPool) PutG2Affine(g *bls12381.G2Affine) {
	if g != nil {
		p.g2AffinePool.Put(g)
	}
}

// GetG2AffineSlice gets a slice of G2 Affine points from the pool
func (p *ObjectPool) GetG2AffineSlice(capacity int) []bls12381.G2Affine {
	slice := p.g2AffineSlicePool.Get().([]bls12381.G2Affine)
	if cap(slice) < capacity {
		return make([]bls12381.G2Affine, 0, capacity)
	}
	return slice[:0]
}

// PutG2AffineSlice returns a slice of G2 Affine points to the pool
func (p *ObjectPool) PutG2AffineSlice(slice []bls12381.G2Affine) {
	if slice != nil {
		p.g2AffineSlicePool.Put(slice)
	}
}

// GetScalarSlice gets a slice of scalars from the pool
func (p *ObjectPool) GetScalarSlice(capacity int) []*big.Int {
	slice := p.scalarSlicePool.Get().([]*big.Int)
	if cap(slice) < capacity {
		return make([]*big.Int, 0, capacity)
	}
	return slice[:0]
}

// PutScalarSlice returns a slice of scalars to the pool
func (p *ObjectPool) PutScalarSlice(slice []*big.Int) {
	if slice != nil {
		p.scalarSlicePool.Put(slice)
	}
}

// GetDisclosedMsgMap gets a map for disclosed messages from the pool
func (p *ObjectPool) GetDisclosedMsgMap() map[int]*big.Int {
	m := p.disclosedMsgPool.Get().(map[int]*big.Int)
	// Clear the map without deallocating
	for k := range m {
		delete(m, k)
	}
	return m
}

// PutDisclosedMsgMap returns a map for disclosed messages to the pool
func (p *ObjectPool) PutDisclosedMsgMap(m map[int]*big.Int) {
	if m != nil {
		p.disclosedMsgPool.Put(m)
	}
}

// GetPointIndexMap gets a map for point indices from the pool
func (p *ObjectPool) GetPointIndexMap() map[int]bls12381.G1Affine {
	m := p.pointIndexPool.Get().(map[int]bls12381.G1Affine)
	// Clear the map without deallocating
	for k := range m {
		delete(m, k)
	}
	return m
}

// PutPointIndexMap returns a map for point indices to the pool
func (p *ObjectPool) PutPointIndexMap(m map[int]bls12381.G1Affine) {
	if m != nil {
		p.pointIndexPool.Put(m)
	}
}

// GetChallengeBuffer gets a buffer for challenge data from the pool
func (p *ObjectPool) GetChallengeBuffer(capacity int) []byte {
	buf := p.challengePool.Get().([]byte)
	if cap(buf) < capacity {
		return make([]byte, 0, capacity)
	}
	return buf[:0]
}

// PutChallengeBuffer returns a buffer for challenge data to the pool
func (p *ObjectPool) PutChallengeBuffer(buf []byte) {
	if buf != nil {
		p.challengePool.Put(buf)
	}
}

// GetMsgBatchMap gets a map for batch message operations from the pool
func (p *ObjectPool) GetMsgBatchMap() map[int][]byte {
	m := p.msgBatchPool.Get().(map[int][]byte)
	// Clear the map without deallocating
	for k := range m {
		delete(m, k)
	}
	return m
}

// PutMsgBatchMap returns a map for batch message operations to the pool
func (p *ObjectPool) PutMsgBatchMap(m map[int][]byte) {
	if m != nil {
		p.msgBatchPool.Put(m)
	}
}

// Global helper functions to use the default pool

// GetBigInt gets a big.Int from the default pool
func GetBigInt() *big.Int {
	return defaultPool.GetBigInt()
}

// PutBigInt returns a big.Int to the default pool
func PutBigInt(i *big.Int) {
	defaultPool.PutBigInt(i)
}

// GetBigIntSlice gets a slice of big.Int pointers from the default pool
func GetBigIntSlice(capacity int) []*big.Int {
	return defaultPool.GetBigIntSlice(capacity)
}

// PutBigIntSlice returns a slice of big.Int pointers to the default pool
func PutBigIntSlice(slice []*big.Int) {
	defaultPool.PutBigIntSlice(slice)
}

// GetG1Jac gets a G1 Jacobian point from the default pool
func GetG1Jac() *bls12381.G1Jac {
	return defaultPool.GetG1Jac()
}

// PutG1Jac returns a G1 Jacobian point to the default pool
func PutG1Jac(g *bls12381.G1Jac) {
	defaultPool.PutG1Jac(g)
}

// GetG1Affine gets a G1 Affine point from the default pool
func GetG1Affine() *bls12381.G1Affine {
	return defaultPool.GetG1Affine()
}

// PutG1Affine returns a G1 Affine point to the default pool
func PutG1Affine(g *bls12381.G1Affine) {
	defaultPool.PutG1Affine(g)
}

// GetG1AffineSlice gets a slice of G1 Affine points from the default pool
func GetG1AffineSlice(capacity int) []bls12381.G1Affine {
	return defaultPool.GetG1AffineSlice(capacity)
}

// PutG1AffineSlice returns a slice of G1 Affine points to the default pool
func PutG1AffineSlice(slice []bls12381.G1Affine) {
	defaultPool.PutG1AffineSlice(slice)
}

// GetG2Jac gets a G2 Jacobian point from the default pool
func GetG2Jac() *bls12381.G2Jac {
	return defaultPool.GetG2Jac()
}

// PutG2Jac returns a G2 Jacobian point to the default pool
func PutG2Jac(g *bls12381.G2Jac) {
	defaultPool.PutG2Jac(g)
}

// GetG2Affine gets a G2 Affine point from the default pool
func GetG2Affine() *bls12381.G2Affine {
	return defaultPool.GetG2Affine()
}

// PutG2Affine returns a G2 Affine point to the default pool
func PutG2Affine(g *bls12381.G2Affine) {
	defaultPool.PutG2Affine(g)
}

// GetG2AffineSlice gets a slice of G2 Affine points from the default pool
func GetG2AffineSlice(capacity int) []bls12381.G2Affine {
	return defaultPool.GetG2AffineSlice(capacity)
}

// PutG2AffineSlice returns a slice of G2 Affine points to the default pool
func PutG2AffineSlice(slice []bls12381.G2Affine) {
	defaultPool.PutG2AffineSlice(slice)
}

// GetScalarSlice gets a slice of scalars from the default pool
func GetScalarSlice(capacity int) []*big.Int {
	return defaultPool.GetScalarSlice(capacity)
}

// PutScalarSlice returns a slice of scalars to the default pool
func PutScalarSlice(slice []*big.Int) {
	defaultPool.PutScalarSlice(slice)
}

// GetDisclosedMsgMap gets a map for disclosed messages from the default pool
func GetDisclosedMsgMap() map[int]*big.Int {
	return defaultPool.GetDisclosedMsgMap()
}

// PutDisclosedMsgMap returns a map for disclosed messages to the default pool
func PutDisclosedMsgMap(m map[int]*big.Int) {
	defaultPool.PutDisclosedMsgMap(m)
}

// GetPointIndexMap gets a map for point indices from the default pool
func GetPointIndexMap() map[int]bls12381.G1Affine {
	return defaultPool.GetPointIndexMap()
}

// PutPointIndexMap returns a map for point indices to the default pool
func PutPointIndexMap(m map[int]bls12381.G1Affine) {
	defaultPool.PutPointIndexMap(m)
}

// GetChallengeBuffer gets a buffer for challenge data from the default pool
func GetChallengeBuffer(capacity int) []byte {
	return defaultPool.GetChallengeBuffer(capacity)
}

// PutChallengeBuffer returns a buffer for challenge data to the default pool
func PutChallengeBuffer(buf []byte) {
	defaultPool.PutChallengeBuffer(buf)
}

// GetMsgBatchMap gets a map for batch message operations from the default pool
func GetMsgBatchMap() map[int][]byte {
	return defaultPool.GetMsgBatchMap()
}

// PutMsgBatchMap returns a map for batch message operations to the default pool
func PutMsgBatchMap(m map[int][]byte) {
	defaultPool.PutMsgBatchMap(m)
}