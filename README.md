# go-witness
A client library for [Witness](https://github.com/in-toto/witness), written in Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/in-toto/go-witness.svg)](https://pkg.go.dev/github.com/in-toto/go-witness)
[![Go Report Card](https://goreportcard.com/badge/github.com/in-toto/go-witness)](https://goreportcard.com/report/github.com/in-toto/go-witness)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8164/badge)](https://www.bestpractices.dev/projects/8164)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/in-toto/go-witness/badge)](https://securityscorecards.dev/viewer/?uri=github.com/in-toto/go-witness)
[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B41709%2Fgithub.com%2Fin-toto%2Fgo-witness.svg?type=shield&issueType=license)](https://app.fossa.com/projects/custom%2B41709%2Fgithub.com%2Fin-toto%2Fgo-witness?ref=badge_shield&issueType=license)

## Status
This library is currently pre-1.0 and therefore the API may be subject to breaking changes.

## Features
- Creation and signing of in-toto attestations
- Verification of in-toto attestations and associated signatures with:
  - Witness policy engine
  - [OPA Rego policy language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- A growing list of attestor types defined under a common interface
- A selection of attestation sources to search for attestation collections
- Resilient Fulcio signer with automatic retry logic and improved error handling for GitHub Actions environments

## Documentation
For more detail regarding the library itself, we recommend viewing [pkg.go.dev](https://pkg.go.dev/github.com/in-toto/go-witness). For
the documentation of the witness project, please view [the main witness repository](https://github.com/in-toto/witness/tree/main/docs).

## Requirements
In order to effectively contribute to this library, you will need:
- A Unix-compatible Operating System
- GNU Make
- Go 1.19

## Fulcio Signer
The Fulcio signer provides certificate-based signing using the [Sigstore Fulcio](https://github.com/sigstore/fulcio) certificate authority. It includes enhanced reliability features for CI/CD environments:

### Retry Logic
- **GitHub Actions OIDC Token Fetching**: Automatic retry with exponential backoff (up to 3 attempts) for transient network issues
- **Fulcio Certificate Creation**: Resilient certificate requests with exponential backoff for service unavailability
- **Smart Error Handling**: Non-retryable errors (authentication, authorization) are detected and fail fast

### Error Handling
- Comprehensive validation of OIDC tokens and certificate responses
- Detailed error messages with context for troubleshooting
- Detection and handling of common failure scenarios (HTML responses, empty responses, invalid tokens)

### Security Improvements
- Updated from SHA256 to SHA384 cryptographic hash for enhanced security
- Validation of certificate chains to ensure all required certificates are present
- Enhanced logging for certificate processing steps while protecting sensitive information

## Running Tests
This repository uses Go tests for testing. You can run these tests by executing `make test`.

## Benchmarking

Performance benchmarks are available for the file attestor to track improvements and detect regressions. Benchmarks use Go's built-in benchmarking framework with CPU and memory profiling via pprof.

### Available Make Targets

- `make benchmark` - Run benchmarks once with profiling (outputs to `benchmark.txt`)
- `make benchmark-stat` - Run benchmarks 10 times with statistical analysis
- `make benchmark-baseline` - Save current benchmark as baseline for future comparisons
- `make benchmark-compare` - Compare current performance against saved baseline
- `make view-cpu` - View CPU profile in browser (requires `benchmark` run first)
- `make view-mem` - View memory profile in browser (requires `benchmark` run first)

### Workflow for Performance Changes

When modifying performance-critical code (e.g., file attestor):

1. **Establish baseline** before making changes:
   ```bash
   make benchmark-baseline
   ```
   This saves results to `benchmark_baseline.txt`

2. **Make your code changes**

3. **Compare against baseline** to measure impact:
   ```bash
   make benchmark-compare
   ```
   This runs new benchmarks and uses `benchstat` to show the comparison

4. **If merging performance improvements**, update the baseline:
   ```bash
   make benchmark-baseline
   ```
   This ensures future changes are compared against the improved baseline

### Understanding Results

The `benchmark-compare` output includes:

- **sec/op** - Execution time per operation (lower is better)
- **MB/op** - Megabytes processed per operation
- **files/sec** - Throughput in files processed (higher is better)
- **MB/sec** - Data throughput (higher is better)
- **B/op** - Memory allocated per operation (lower is better)
- **allocs/op** - Allocation count per operation (lower is better)

Statistical indicators:
- Percentage with sign shows direction: `-34.16%` means 34% faster, `+15%` means slower
- `~` indicates no significant change detected
- `(p=0.000 n=10)` shows statistical confidence from 10 runs

### Analyzing Performance with pprof

After running `make benchmark`, analyze bottlenecks:

```bash
# Interactive web UI at localhost:6060
make view-cpu   # View CPU profile with flamegraphs and call graphs
make view-mem   # View memory allocation profile
```

The pprof web UI provides:
- **Graph** - Call graph showing where time/memory is spent
- **Flame Graph** - Visual hierarchy of execution paths
- **Top** - Functions ranked by resource usage
- **Source** - Annotated source code with line-by-line metrics
