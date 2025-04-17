package main

import (
	"fmt"
	"reflect"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// List all methods of a type
func listMethods(obj interface{}) {
	t := reflect.TypeOf(obj)
	fmt.Printf("Methods for %s:\n", t.String())
	for i := 0; i < t.NumMethod(); i++ {
		method := t.Method(i)
		fmt.Printf("  - %s\n", method.Name)
	}
	fmt.Println()
}

func main() {
	// Get generators
	_, _, g1, g2 := bls12381.Generators()
	fmt.Printf("G1 generator: %T\n", g1)
	fmt.Printf("G2 generator: %T\n", g2)
	
	// List methods for G1Affine
	listMethods(g1)
	
	// List methods for G1Jac
	g1jac := bls12381.G1Jac{}
	g1jac.FromAffine(&g1)
	listMethods(g1jac)
	
	// Try different ways to convert Jacobian to Affine
	fmt.Println("Trying to convert from Jacobian to Affine...")
	
	// Try using String() method to investigate
	fmt.Printf("Original G1: %s\n", g1.String())
	fmt.Printf("G1Jac: %s\n", g1jac.String())
	
	// Try direct conversion
	//g1aff := g1jac.ToAffine()
	
	// Try using bls12381.Pair
	fmt.Println("\nPairing API test:")
	res, err := bls12381.Pair([]bls12381.G1Affine{g1}, []bls12381.G2Affine{g2})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Pairing result: %v\n", res)
	}
}