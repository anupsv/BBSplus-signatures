// Command bench runs benchmarks for the BBS+ library
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/asv/bbs/bbs/benchmarks"
)

func main() {
	// Define command line flags
	name := flag.String("name", "Default", "Name of the benchmark")
	messages := flag.Int("messages", 10, "Number of messages to sign")
	disclosed := flag.Int("disclosed", 3, "Number of messages to disclose in proofs")
	iterations := flag.Int("iterations", 100, "Number of iterations for each benchmark")
	batchOps := flag.Bool("batch", true, "Use batch operations where applicable")
	concurrent := flag.Bool("concurrent", true, "Use concurrent operations where applicable")
	_ = flag.Int("max-time", 0, "Maximum time per operation in milliseconds (0 = unlimited)") // Unused but kept for CLI compatibility
	output := flag.String("output", "", "Output file path (empty for stdout)")
	format := flag.String("format", "text", "Output format (text, json, csv, html)")
	
	flag.Parse()
	
	// Create benchmark configuration
	config := benchmarks.BenchmarkConfig{
		Name:           *name,
		MessageCount:   *messages,
		DisclosedCount: *disclosed,
		Iterations:     *iterations,
		UseBatch:       *batchOps,
		UseConcurrent:  *concurrent,
	}
	
	// Validate configuration
	if config.MessageCount < 1 {
		fmt.Fprintln(os.Stderr, "Error: Message count must be at least 1")
		os.Exit(1)
	}
	
	if config.DisclosedCount < 1 || config.DisclosedCount > config.MessageCount {
		fmt.Fprintf(os.Stderr, "Error: Disclosed count must be between 1 and %d\n", config.MessageCount)
		os.Exit(1)
	}
	
	if config.Iterations < 1 {
		fmt.Fprintln(os.Stderr, "Error: Iterations must be at least 1")
		os.Exit(1)
	}
	
	// Create benchmark runner
	runner := benchmarks.NewRunner(config)
	
	// Run benchmarks
	fmt.Println("Running BBS+ benchmarks...")
	results, err := runner.RunAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running benchmarks: %v\n", err)
		os.Exit(1)
	}
	
	// Create reporter based on output format
	reporter := benchmarks.NewReporter(
		benchmarks.OutputFormat(strings.ToLower(*format)),
		*output,
	)
	
	// Report results
	err = reporter.Report(results)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reporting results: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("Benchmarks completed successfully!")
}