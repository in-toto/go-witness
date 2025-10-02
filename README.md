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
