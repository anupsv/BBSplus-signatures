// +build js,wasm

package wasm

import "syscall/js"

// Main is the entry point for the WASM build
func Main() {
	// Initialize the WASM bindings
	js.Global().Set("onBBSModuleReady", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// Initialize the BBS object and register all functions
		Initialize()
		
		// Notify that the module is ready
		if len(args) > 0 && !args[0].IsUndefined() && args[0].Type() == js.TypeFunction {
			// Call the ready callback if provided
			args[0].Invoke()
		}
		
		return nil
	}))
	
	// Resolve the module initialization promise
	js.Global().Call("bbsModuleReady")
	
	// Keep the program running
	select {}
}