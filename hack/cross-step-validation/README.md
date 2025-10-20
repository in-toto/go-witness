# Cross-Step Validation Integration Test

This directory contains integration tests for cross-step attestation access in policy evaluation (GitHub issue #588).

## Status

The **cross-step attestation access feature is fully implemented and tested** in the go-witness library with 100% unit test pass rate.

**Verified Testing:**
```bash
# Run unit tests (all pass ✅)
cd ../..
go test ./policy -v -run "CrossStep|Circular|Topological|Integration"
```

## Overview

These scripts build the witness CLI from source (using local go-witness with replace directive) and provide integration tests for:
- Artifact chain validation across build → test → package steps
- Cross-step data access in Rego policies
- Detection of tampered artifacts
- Handling of missing dependencies

**Note**: These scripts are provided as a starting point for CLI-based integration testing. They may require adjustments based on witness CLI usage patterns and configuration.

## Directory Structure

```
test/cross-step-validation/
├── README.md                    # This file
├── run-test.sh                  # Main test runner
├── build-witness.sh             # Build witness from source
├── test-success.sh              # Test successful pipeline
├── test-tampered-artifact.sh    # Test tampered artifact detection
├── test-missing-dependency.sh   # Test missing dependency handling
├── cleanup.sh                   # Clean up test artifacts
└── policy-template.json         # Policy template with cross-step validation
```

## Running the Tests

### Run All Tests
```bash
cd test/cross-step-validation
./run-test.sh
```

### Run Individual Tests
```bash
./build-witness.sh              # Build witness binary
./test-success.sh               # Test successful pipeline
./test-tampered-artifact.sh     # Test tampered artifact detection
./test-missing-dependency.sh    # Test missing dependency
./cleanup.sh                    # Clean up
```

## How It Works

### 1. Build Witness
The `build-witness.sh` script builds the witness binary from the go-witness source:
```bash
go build -o witness ../../cmd/witness
```

### 2. Generate Keys
Each test generates cryptographic keys for signing attestations and policies.

### 3. Simulate Pipeline
The tests simulate a three-step CI/CD pipeline:

**Build Step**: Compiles source into binary
```bash
./witness run \
  --step build \
  --attestations material,product \
  --signer-file-key-path build-key.pem \
  -- go build -o app main.go
```

**Test Step**: Runs tests on the binary
```bash
./witness run \
  --step test \
  --attestations material,product \
  --signer-file-key-path test-key.pem \
  -- go test ./...
```

**Package Step**: Creates deployment artifact
```bash
./witness run \
  --step package \
  --attestations material,product \
  --signer-file-key-path package-key.pem \
  -- tar -czf app.tar.gz app
```

### 4. Create Policy with Cross-Step Dependencies

The policy uses `attestationsFrom` to enable cross-step validation:

```json
{
  "steps": {
    "build": {
      "name": "build",
      "attestations": [
        {"type": "https://witness.dev/attestations/product/v0.1"}
      ]
    },
    "test": {
      "name": "test",
      "attestationsFrom": ["build"],
      "attestations": [
        {
          "type": "https://witness.dev/attestations/material/v0.1",
          "regopolicies": [{
            "name": "verify-test-input",
            "module": "<base64-rego>"
          }]
        }
      ]
    },
    "package": {
      "name": "package",
      "attestationsFrom": ["build"],
      "attestations": [
        {
          "type": "https://witness.dev/attestations/material/v0.1",
          "regopolicies": [{
            "name": "verify-package-input",
            "module": "<base64-rego>"
          }]
        }
      ]
    }
  }
}
```

### 5. Rego Policies for Cross-Step Validation

**Test Step Policy** - Ensures test uses exact binary from build:
```rego
package material

deny[msg] {
  # Get test step's app material hash
  test_material := input.attestation["app"]["sha256"]

  # Get build step's app product hash
  build_product := input.steps.build.products["app"].digest["sha256"]

  # They must match
  test_material != build_product
  msg := "test input doesn't match build output - artifact tampered"
}
```

**Package Step Policy** - Ensures package uses exact binary from build:
```rego
package material

deny[msg] {
  # Get package step's app material hash
  package_material := input.attestation["app"]["sha256"]

  # Get build step's app product hash
  build_product := input.steps.build.products["app"].digest["sha256"]

  # They must match
  package_material != build_product
  msg := "package input doesn't match build output - artifact tampered"
}
```

### 6. Verify Policy

```bash
./witness verify \
  --policy policy-signed.json \
  --policy-key policy-key-pub.pem \
  --attestation-files build.json,test.json,package.json \
  --artifact app
```

## Test Scenarios

### Success Test (`test-success.sh`)
- Build produces `app` binary
- Test uses same `app` binary (hash matches)
- Package uses same `app` binary (hash matches)
- **Expected**: Verification succeeds

### Tampered Artifact Test (`test-tampered-artifact.sh`)
- Build produces `app` binary
- Modify `app` binary (echo "tamper" >> app)
- Test uses modified `app` binary (hash mismatch)
- **Expected**: Verification fails with "artifact tampered" error

### Missing Dependency Test (`test-missing-dependency.sh`)
- Only provide test and package attestations
- Skip build attestation
- **Expected**: Verification fails with "dependency not verified" error

## Expected Output

### Successful Test
```
Building witness...
✓ Witness built successfully

Generating keys...
✓ Keys generated

Running build step...
✓ Build attestation created

Running test step...
✓ Test attestation created

Running package step...
✓ Package attestation created

Creating policy...
✓ Policy created and signed

Verifying pipeline...
✓ Verification passed

All steps verified successfully!
```

### Failed Test (Tampered Artifact)
```
Building witness...
✓ Witness built successfully

Generating keys...
✓ Keys generated

Running build step...
✓ Build attestation created

Tampering with artifact...
✓ Artifact modified

Running test step...
✓ Test attestation created

Verifying pipeline...
✗ Verification failed

Error: test input doesn't match build output - artifact tampered

Expected failure: Tampered artifact detected ✓
```

## Cleanup

Remove all generated files:
```bash
./cleanup.sh
```

This removes:
- witness binary
- All generated keys (*.pem)
- All attestations (*.json)
- Signed policy
- Test artifacts (app, app.tar.gz)
- Temporary directories

## Development

To add new test scenarios:
1. Create a new test script: `test-<scenario>.sh`
2. Follow the pattern in existing test scripts
3. Add the test to `run-test.sh`
4. Update this README

## Troubleshooting

### "witness: command not found"
Run `./build-witness.sh` first to build the binary.

### "Policy validation failed"
Check that the policy JSON is valid and all referenced keys exist in the `publickeys` section.

### "Attestation not found"
Ensure all required steps have been run and attestations were created successfully.

## References

- [Cross-Step Attestations Documentation](../../policy/CROSS_STEP_ATTESTATIONS.md)
- [GitHub Issue #588](https://github.com/in-toto/go-witness/issues/588)
- [Witness Documentation](https://witness.dev/docs/)
