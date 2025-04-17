.PHONY: all clean server

# Variables
GOOS=js
GOARCH=wasm
OUTPUT=main.wasm
WASMEXEC=$(shell go env GOROOT)/misc/wasm/wasm_exec.js

all: $(OUTPUT) wasm_exec.js

# Build the WebAssembly binary
$(OUTPUT): main.go
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(OUTPUT) main.go

# Copy wasm_exec.js from Go distribution
wasm_exec.js:
	cp $(WASMEXEC) .

# Start a simple HTTP server
server: all
	go run server.go

# Clean up
clean:
	rm -f $(OUTPUT) wasm_exec.js