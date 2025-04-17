#\!/bin/bash

# Compile the BBS+ WASM module
echo "Compiling BBS+ WASM module..."
GOOS=js GOARCH=wasm go build -o main.wasm main.go
if [ $? -ne 0 ]; then
    echo "Compilation failed\!"
    exit 1
fi

# Copy wasm_exec.js from the Go installation
GOROOT=$(go env GOROOT)
WASMEXEC="$GOROOT/misc/wasm/wasm_exec.js"
echo "Copying $WASMEXEC to current directory..."
cp "$WASMEXEC" .
if [ $? -ne 0 ]; then
    echo "Failed to copy wasm_exec.js\!"
    exit 1
fi

echo "Build completed successfully\!"
echo "To run the demo: go run server.go"
