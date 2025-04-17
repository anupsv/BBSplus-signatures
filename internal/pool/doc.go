// Package pool provides memory optimization through object pooling.
//
// It implements pooling for frequently used objects such as big integers,
// points on elliptic curves, and slices. This helps reduce memory allocations
// and garbage collection overhead, improving performance for cryptographic operations.
//
// The pools are sized based on typical usage patterns in BBS+ operations,
// and objects are automatically returned to the pool when no longer needed.
//
// This is an internal package not intended for direct use by applications.
// It is used by the core BBS+ implementation to optimize memory usage.
package pool

// Pool types
const (
	// PoolSize is the default size for object pools
	PoolSize = 100
	
	// BigIntPoolSize is the size of the big.Int pool
	BigIntPoolSize = 200
	
	// PointPoolSize is the size of the elliptic curve point pool
	PointPoolSize = 50
	
	// SlicePoolSize is the size of the slice pool
	SlicePoolSize = 20
)