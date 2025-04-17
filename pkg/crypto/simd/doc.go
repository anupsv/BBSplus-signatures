// Package simd provides SIMD (Single Instruction, Multiple Data) accelerated
// implementations of cryptographic operations for the BBS+ signature scheme.
//
// This package detects the CPU capabilities at runtime and selects the
// most appropriate implementation based on the available SIMD instructions:
//
// - AVX2 (Advanced Vector Extensions 2) for x86_64/amd64 CPUs
// - AVX512 for newer x86_64/amd64 CPUs with AVX512 support
// - NEON for ARM64 CPUs
//
// The main optimization is for multi-scalar multiplication (MSM), which is a
// performance bottleneck in BBS+ signature operations. By using SIMD instructions,
// we can process multiple points and scalars in parallel, significantly improving
// performance.
//
// Usage:
//
//     // Use automatic optimization selection
//     result, err := simd.MultiScalarMulG1(points, scalars, simd.OptimizationAuto)
//
//     // Force a specific optimization level
//     result, err := simd.MultiScalarMulG1(points, scalars, simd.OptimizationAVX2)
//
// This package is used internally by the crypto package for improved performance,
// but can also be used directly for applications with specific optimization needs.
package simd

// OptimizationDefaults is the recommended optimization level for most applications
const OptimizationDefaults = OptimizationAuto