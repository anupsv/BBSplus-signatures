# BBS+ Signatures WebAssembly Module

This directory contains a WebAssembly (WASM) wrapper for the BBS+ signatures library, allowing it to be used in web browsers and other JavaScript environments.

## Features

- Generate BBS+ key pairs
- Sign messages with BBS+
- Verify BBS+ signatures
- Create selective disclosure proofs
- Verify selective disclosure proofs

## Building the WASM Module

To build the WebAssembly module, you need Go 1.16 or later. Run:

```bash
make
```

This will:
1. Compile the Go code to WebAssembly (main.wasm)
2. Copy the required wasm_exec.js file from your Go installation

## Running the Demo

To run the demo locally:

```bash
make server
```

This starts a local web server at http://localhost:8080. Open this URL in your browser to use the demo.

## API Reference

The WASM module exposes the following JavaScript functions:

### generateKeyPair(messageCount)

Generates a new BBS+ key pair for signing the specified number of messages.

**Parameters:**
- `messageCount`: Number of messages the key pair will support

**Returns:**
- Object with `success` flag, `privateKey` and `publicKey` (Base64-encoded)

### sign(privateKey, publicKey, messagesJson)

Signs a set of messages using BBS+.

**Parameters:**
- `privateKey`: Base64-encoded private key
- `publicKey`: Base64-encoded public key
- `messagesJson`: JSON string containing `{ "messages": ["msg1", "msg2", ...] }`

**Returns:**
- Object with `success` flag and `signature` (Base64-encoded)

### verify(publicKey, signature, messagesJson)

Verifies a BBS+ signature on a set of messages.

**Parameters:**
- `publicKey`: Base64-encoded public key
- `signature`: Base64-encoded signature
- `messagesJson`: JSON string containing `{ "messages": ["msg1", "msg2", ...] }`

**Returns:**
- Object with `success` and `verified` flags

### createProof(proofRequestJson)

Creates a selective disclosure proof.

**Parameters:**
- `proofRequestJson`: JSON string containing:
  ```json
  {
    "messages": ["msg1", "msg2", ...],
    "disclosedIndices": [0, 2, ...],
    "signature": "base64-signature",
    "publicKey": "base64-public-key"
  }
  ```

**Returns:**
- Object with `success` flag, `proof` (Base64-encoded) and `disclosedMessages` map

### verifyProof(verifyRequestJson)

Verifies a selective disclosure proof.

**Parameters:**
- `verifyRequestJson`: JSON string containing:
  ```json
  {
    "proof": "base64-proof",
    "disclosedMessages": {"0": "msg-value-1", "2": "msg-value-2"},
    "publicKey": "base64-public-key"
  }
  ```

**Returns:**
- Object with `success` and `verified` flags

## Integration with Other Applications

To use this WASM module in your own application:

1. Copy `main.wasm` and `wasm_exec.js` to your web application
2. Load the WASM module in your JavaScript code:

```javascript
// Initialize the Go WASM runtime
const go = new Go();
WebAssembly.instantiateStreaming(fetch("main.wasm"), go.importObject)
  .then((result) => {
    go.run(result.instance);
    console.log("WASM module loaded");
    
    // Now you can use the exported functions
    const keyPair = generateKeyPair(5);
    // ...
  });
```

## Browser Compatibility

This WASM module works with all modern browsers that support WebAssembly, including:

- Chrome 57+
- Firefox 53+
- Safari 11+
- Edge 16+

## Known Limitations

- The marshaling of keys and signatures may not be compatible with other BBS+ implementations
- Browser memory constraints may limit the size of messages that can be processed
- Performance may vary depending on the browser and device