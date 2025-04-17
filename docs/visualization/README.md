# BBS+ Proof Visualization Tools

This directory contains tools for visualizing the BBS+ proof creation and verification process. These visualizations help developers and users understand how selective disclosure proofs work.

## Overview

BBS+ proof creation and verification involve complex cryptographic operations. These visualization tools make it easier to:

1. Understand which messages are disclosed vs. hidden
2. See how the proof is constructed
3. Follow the verification process
4. Analyze the performance of different operations

## Tools Included

### 1. Interactive Proof Visualizer

The `proofvis` tool provides an interactive web-based visualization of the proof creation and verification process. It shows:

- The original signed messages
- Which messages are disclosed vs. hidden
- The transformation of the signature
- The generation of blinding factors
- The creation of commitments
- The challenge generation
- The response calculation

### 2. Performance Visualizer

The `perfvis` tool visualizes the performance of different cryptographic operations in the BBS+ library:

- Multi-scalar multiplication
- Pairing operations
- Hash-to-curve operations
- Batch verification

### 3. Dependency Graph

The `depgraph` tool generates a graph showing the dependencies between different parts of the proof:

- How disclosed messages affect the proof
- How hidden messages are blinded
- How the signature is transformed

## Usage

### Interactive Proof Visualizer

```
cd visualization
go run cmd/proofvis/main.go
```

Then open your browser to `http://localhost:8080` to see the interactive visualization.

### Performance Visualizer

```
cd visualization
go run cmd/perfvis/main.go --benchmark ./benchmark_results.json
```

This will generate an HTML file with interactive charts showing the performance of different operations.

### Dependency Graph

```
cd visualization
go run cmd/depgraph/main.go --output graph.svg
```

This will generate an SVG file showing the dependencies between different parts of the proof.

## Implementation Details

These tools are built using:

- [D3.js](https://d3js.org/) for interactive visualizations
- [Go templates](https://golang.org/pkg/html/template/) for generating HTML
- [WebAssembly](https://webassembly.org/) for interactive elements

## Screenshots

### Proof Visualization

![Proof Visualization](./images/proof_visualization.png)

### Performance Visualization

![Performance Visualization](./images/performance_visualization.png)

### Dependency Graph

![Dependency Graph](./images/dependency_graph.png)