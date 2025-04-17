//go:build js && wasm

package main

func init() {
	// Initialize WASM when the module is loaded
	Initialize()
}

func main() {
	// Create a channel to keep the program running
	c := make(chan struct{})
	<-c
}