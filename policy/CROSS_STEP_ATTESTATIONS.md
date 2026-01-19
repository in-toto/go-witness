# Cross-Step Attestation Access in Policy Evaluation

## Overview

Cross-step attestation access allows Rego policies to dynamically access attestation data from dependent steps during policy evaluation. This enables validation of artifact chains and multi-step supply chain integrity without hardcoding expected values in policies.

## Key Features

### 1. AttestationsFrom Field
The `AttestationsFrom` field in the Step struct declares dependencies on other steps' attestation data.

```json
{
  "steps": {
    "build": {
      "name": "build",
      "attestations": [
        {"type": "https://witness.dev/attestations/product/v0.1"}
      ]
    },
    "package": {
      "name": "package",
      "attestationsFrom": ["build"],
      "attestations": [
        {
          "type": "https://witness.dev/attestations/material/v0.1",
          "regopolicies": [{
            "name": "verify-chain",
            "module": "<base64-rego>"
          }]
        }
      ]
    }
  }
}
```

### 2. Enhanced Rego Input Structure

When a step declares `AttestationsFrom`, the Rego policy receives enhanced input:

```json
{
  "attestation": {
    // Current step's attestation data (backward compatible)
  },
  "steps": {
    "<step-name>": {
      "products": {/* product attestation data */},
      "materials": {/* material attestation data */},
      "command": {/* command-run attestation data */},
      "environment": {/* environment attestation data */},
      "git": {/* git attestation data */}
    }
  }
}
```

### 3. Circular Dependency Protection

The system automatically detects and prevents circular dependencies at policy load time:
- Self-references (step depending on itself)
- Direct cycles (A → B → A)
- Indirect cycles (A → B → C → A)

### 4. Dependency-Ordered Evaluation

Steps are evaluated in topological order, ensuring dependencies are always verified first:
1. Steps with no dependencies are evaluated first
2. Dependent steps are evaluated only after their dependencies pass
3. Failed dependencies cascade to dependent steps

## Security Model

### Threat Mitigation

1. **Malicious Rego Policy Access**: Only explicitly declared dependencies in `AttestationsFrom` are accessible
2. **Unverified Data Access**: Only data from PASSED collections is included in the context
3. **Circular Dependencies**: Detected at policy load time with fail-fast behavior
4. **Race Conditions**: Deterministic topological sort ensures consistent evaluation order
5. **Transitive Access**: No transitive access - each step must explicitly declare ALL dependencies

### Principle of Least Privilege

- Steps can only access data from explicitly declared dependencies
- No transitive access through intermediate steps
- Unverified or failed dependencies are excluded from context

## Usage Examples

### Example 1: Artifact Chain Validation

Verify that the package step's input matches the build step's output:

**Policy Configuration:**
```json
{
  "steps": {
    "build": {
      "name": "build",
      "attestations": [
        {"type": "https://witness.dev/attestations/product/v0.1"}
      ],
      "functionaries": [{"type": "publickey", "publickeyid": "builder-key"}]
    },
    "package": {
      "name": "package",
      "attestationsFrom": ["build"],
      "attestations": [
        {
          "type": "https://witness.dev/attestations/material/v0.1",
          "regopolicies": [{
            "name": "artifact-chain",
            "module": "cGFja2FnZSBtYXRlcmlhbAoKZGVueVttc2ddIHsKICBwYWNrYWdlX21hdGVyaWFsIDo9IGlucHV0LmF0dGVzdGF0aW9uWyJhcHAiXVsic2hhMjU2Il0KICBidWlsZF9wcm9kdWN0IDo9IGlucHV0LnN0ZXBzLmJ1aWxkLnByb2R1Y3RzWyJhcHAiXS5kaWdlc3RbInNoYTI1NiJdCiAgcGFja2FnZV9tYXRlcmlhbCAhPSBidWlsZF9wcm9kdWN0CiAgbXNnIDo9ICJhcnRpZmFjdCBjaGFpbiBicm9rZW4gLSBhcHAgd2FzIHRhbXBlcmVkIGJldHdlZW4gYnVpbGQgYW5kIHBhY2thZ2UiCn0K"
          }]
        }
      ],
      "functionaries": [{"type": "publickey", "publickeyid": "packager-key"}]
    }
  },
  "publickeys": {
    "builder-key": {...},
    "packager-key": {...}
  }
}
```

**Rego Policy (decoded):**
```rego
package material

deny[msg] {
  # Get package step's input material hash
  package_material := input.attestation["app"]["sha256"]

  # Get build step's output product hash
  build_product := input.steps.build.products["app"].digest["sha256"]

  # Verify they match
  package_material != build_product
  msg := "artifact chain broken - app was tampered between build and package"
}
```

### Example 2: Multi-Step Validation

Validate data flows through multiple steps:

```json
{
  "steps": {
    "source": {
      "name": "source",
      "attestations": [
        {"type": "https://witness.dev/attestations/git/v0.1"},
        {"type": "https://witness.dev/attestations/product/v0.1"}
      ]
    },
    "build": {
      "name": "build",
      "attestationsFrom": ["source"],
      "attestations": [
        {
          "type": "https://witness.dev/attestations/material/v0.1",
          "regopolicies": [{
            "name": "verify-source",
            "module": "<base64-rego-to-verify-git-commit>"
          }]
        },
        {"type": "https://witness.dev/attestations/product/v0.1"}
      ]
    },
    "test": {
      "name": "test",
      "attestationsFrom": ["build"],
      "attestations": [
        {
          "type": "https://witness.dev/attestations/command-run/v0.1",
          "regopolicies": [{
            "name": "verify-test-inputs",
            "module": "<base64-rego-to-verify-test-used-built-artifacts>"
          }]
        }
      ]
    },
    "package": {
      "name": "package",
      "attestationsFrom": ["build", "test"],
      "attestations": [
        {
          "type": "https://witness.dev/attestations/material/v0.1",
          "regopolicies": [{
            "name": "verify-packaging",
            "module": "<base64-rego-to-verify-only-tested-artifacts-packaged>"
          }]
        }
      ]
    }
  }
}
```

### Example 3: Environment Consistency

Ensure consistent build environment across steps:

```rego
package environment

deny[msg] {
  # Check that test ran with same Go version as build
  build_go := input.steps.build.environment.variables["GOVERSION"]
  test_go := input.attestation.variables["GOVERSION"]
  build_go != test_go
  msg := sprintf("Go version mismatch: build used %s, test used %s", [build_go, test_go])
}
```

### Example 4: Accessing Any Attestation Type

All attestations from dependent steps are available via the `attestations` map:

```rego
package material

deny[msg] {
  # Access lockfile attestation from build step
  lockfile_att := input.steps.build.attestations["https://witness.dev/attestations/lockfiles/v0.1"]

  # Access SBOM attestation
  sbom_att := input.steps.build.attestations["https://witness.dev/attestations/sbom/v0.1"]

  # Access any custom attestation type
  custom_att := input.steps.build.attestations["https://custom.com/attestations/my-type/v1.0"]

  # Validate something about the attestation
  not lockfile_att
  msg := "build step missing lockfile attestation"
}
```

**Note**: The `attestations` map provides access to ALL attestation types from dependent steps, not just products/materials. This allows Rego policies to validate any attestation data including lockfiles, SBOMs, security scans, custom attestations, etc.

## Implementation Details

### Backward Compatibility

The implementation maintains full backward compatibility:
- Existing policies without `AttestationsFrom` work unchanged
- The `attestation` field in Rego input remains at the top level
- Variadic parameter in `EvaluateRegoPolicy()` preserves API compatibility

### Performance Considerations

- Topological sort runs once per verification (O(V+E) complexity)
- Step context is built lazily only for steps with dependencies
- No additional attestation fetching - uses already verified data

### Error Handling

1. **Circular Dependencies**: `ErrCircularDependency` at policy load
2. **Self-References**: `ErrSelfReference` at policy load
3. **Unverified Dependencies**: `ErrDependencyNotVerified` during evaluation
4. **Cascade Failures**: Dependent steps automatically fail if dependencies fail

## Migration Guide

### Adding Cross-Step Validation to Existing Policies

1. **Identify Dependencies**: Determine which steps need data from other steps

2. **Add AttestationsFrom**: Update step definitions:
   ```json
   "package": {
     "attestationsFrom": ["build"],
     ...
   }
   ```

3. **Update Rego Policies**: Modify Rego to use cross-step data:
   ```rego
   # Before (hardcoded expected value)
   deny[msg] {
     input["app"]["sha256"] != "expected-hash-abc123"
     msg := "unexpected artifact"
   }

   # After (dynamic validation)
   deny[msg] {
     package_hash := input.attestation["app"]["sha256"]
     build_hash := input.steps.build.products["app"].digest["sha256"]
     package_hash != build_hash
     msg := "artifact chain broken"
   }
   ```

4. **Test Thoroughly**: Ensure policies still pass with valid attestations

## Best Practices

1. **Explicit Dependencies**: Only declare dependencies you actually need
2. **Fail-Safe Policies**: Handle missing data gracefully in Rego
3. **Validate Early**: Check dependencies at the earliest possible step
4. **Document Dependencies**: Comment why each dependency is needed
5. **Test Negative Cases**: Ensure policies correctly reject invalid chains

## Troubleshooting

### Common Issues

1. **"Circular dependency detected"**
   - Check for cycles in AttestationsFrom declarations
   - Use `policy.Validate()` to identify the cycle

2. **"Dependency 'X' not verified"**
   - Ensure dependency step has valid attestations
   - Check functionary configuration for dependency step

3. **"Cannot access input.steps.X"**
   - Verify step X is listed in AttestationsFrom
   - Confirm step X has PASSED collections

4. **Policy passes when it should fail**
   - Check Rego logic for proper field access
   - Verify attestation data structure matches expectations
   - Test with known-bad attestations

## API Reference

### Policy Struct Changes

```go
type Step struct {
    Name             string        `json:"name"`
    Functionaries    []Functionary `json:"functionaries"`
    Attestations     []Attestation `json:"attestations"`
    ArtifactsFrom    []string      `json:"artifactsFrom,omitempty"`
    AttestationsFrom []string      `json:"attestationsFrom,omitempty"`  // NEW
}
```

### Validation Methods

```go
// Validate checks for circular dependencies
func (p Policy) Validate() error

// Returns steps in dependency order
func (p Policy) topologicalSort() ([]string, error)
```

### Error Types

```go
// Step references itself in AttestationsFrom
type ErrSelfReference struct {
    Step string
}

// Circular dependency chain detected
type ErrCircularDependency struct {
    Steps []string  // Steps forming the cycle
}

// Required dependency not verified
type ErrDependencyNotVerified struct {
    Step string
}
```

## Testing

The implementation includes comprehensive test coverage:

- **Unit Tests**: Individual function testing
- **Integration Tests**: End-to-end artifact chain validation
- **Cycle Detection Tests**: Various circular dependency scenarios
- **Topological Sort Tests**: Ordering validation
- **Rego Evaluation Tests**: Cross-step data access validation

Run tests with:
```bash
go test ./policy -v -run "CrossStep|Circular|Topological"
```

## Future Enhancements

Potential improvements for future versions:

1. **Transitive Access Control**: Optional flag to allow transitive dependencies
2. **Dependency Versioning**: Support for attestation version compatibility
3. **Performance Metrics**: Track dependency resolution overhead
4. **Visualization Tools**: Generate dependency graphs from policies
5. **Schema Validation**: JSON Schema for attestation data structure