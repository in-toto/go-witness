# Cross-Step Attestation Access - Threat Model

This document describes the security threat model for the cross-step attestation access feature and how it is validated through comprehensive unit tests.

## Overview

The cross-step attestation access feature allows policy steps to access attestation data from their declared dependencies during Rego policy evaluation. This introduces several security considerations that must be carefully managed to prevent attacks.

## Threat Categories

### 1. **Circular Dependency Attacks**

**Threat**: Attacker creates circular dependencies in policy to cause infinite loops, resource exhaustion, or bypass verification order.

**Mitigation**:
- DFS-based cycle detection at policy load time (before any verification)
- Topological sort ensures dependency-ordered evaluation
- Self-reference detection prevents `step → step` cycles
- Transitive cycle detection prevents `A → B → C → A` cycles

**Validated by**:
- `TestThreatModel_CircularDependencyAttack` - Tests direct cycles, self-references, and indirect cycles
- `TestCircularDependencyDetection` - Comprehensive cycle detection tests

### 2. **Unverified Data Access**

**Threat**: Steps access data from dependencies that haven't been verified or failed verification, potentially using compromised attestation data.

**Mitigation**:
- Only data from PASSED collections is accessible
- Steps with no passed collections contribute zero data
- Dependency verification state checked before step evaluation

**Validated by**:
- `TestThreatModel_UnverifiedStepDataIsolation` - Ensures failed steps don't leak data
- `TestThreatModel_PartialVerificationDataIsolation` - Only passed data accessible
- `TestThreatModel_MissingDependencyPreventsExecution` - Missing deps block execution
- `TestThreatModel_FailedDependencyPreventsExecution` - Failed deps block execution

### 3. **Data Isolation Violations**

**Threat**: Steps access data from steps they haven't explicitly declared as dependencies, violating least-privilege principle.

**Mitigation**:
- Only explicitly declared dependencies are accessible
- Empty dependency list = no cross-step access
- Non-existent dependencies result in empty context (safe failure)

**Validated by**:
- `TestThreatModel_DataIsolationBetweenSteps` - Only declared deps accessible
- `TestThreatModel_EmptyDependencyListIsSecure` - No deps = no access
- `TestThreatModel_NonExistentDependencyIsSecure` - Safe failure mode

### 4. **Cascading Failures**

**Threat**: Single step failure doesn't propagate, allowing dependent steps to execute with invalid assumptions.

**Mitigation**:
- Topological sort ensures dependencies evaluated first
- Failed dependency blocks all transitive dependents
- Clear error messages for dependency failures

**Validated by**:
- `TestThreatModel_CascadingFailure` - Failure propagation verification
- `TestCheckDependencies` - Dependency verification before evaluation

### 5. **Execution Order Manipulation**

**Threat**: Attacker manipulates policy declaration order to execute steps before their dependencies are verified.

**Mitigation**:
- Topological sort overrides declaration order
- Kahn's algorithm ensures correct dependency order
- Dependencies always evaluated before dependents

**Validated by**:
- `TestThreatModel_TopologicalSortPreventsEarlyExecution` - Order enforcement
- `TestTopologicalSort` - Algorithm correctness

### 6. **Type Spoofing**

**Threat**: Attacker creates attestations with "product" or "material" in type string but doesn't implement the actual interfaces, potentially bypassing validation.

**Mitigation**:
- Interface-based detection using type assertions
- No string pattern matching for type detection
- Only attestations implementing `Producer`/`Materialer` interfaces are recognized

**Validated by**:
- `TestThreatModel_InterfaceBasedDetectionPreventsTypeSpoofing` - Verifies interface-based detection

## Security Properties

The threat model tests validate these critical security properties:

### ✅ Confidentiality
- Steps cannot access data from undeclared dependencies
- Failed attestations don't leak their data
- Explicit opt-in required for cross-step access

### ✅ Integrity
- Only verified (PASSED) attestations contribute data
- Circular dependencies detected before verification
- Dependency order enforced via topological sort

### ✅ Availability
- Circular dependencies don't cause infinite loops
- Failed dependencies block dependents (fail-safe)
- Resource exhaustion attacks prevented

### ✅ Least Privilege
- Steps only access explicitly declared dependencies
- Empty declarations = zero access
- Non-existent dependencies result in empty context

## Test Coverage

The security test suite (`policy/security_test.go`) provides comprehensive coverage:

| Test | Lines | Purpose |
|------|-------|---------|
| `TestThreatModel_UnverifiedStepDataIsolation` | 67 | Prevents data leakage from failed steps |
| `TestThreatModel_PartialVerificationDataIsolation` | 74 | Only passed data accessible |
| `TestThreatModel_MissingDependencyPreventsExecution` | 31 | Blocks execution on missing deps |
| `TestThreatModel_FailedDependencyPreventsExecution` | 37 | Blocks execution on failed deps |
| `TestThreatModel_CircularDependencyAttack` | 86 | Comprehensive cycle detection |
| `TestThreatModel_DataIsolationBetweenSteps` | 74 | Explicit dependency enforcement |
| `TestThreatModel_EmptyDependencyListIsSecure` | 28 | Zero access with no deps |
| `TestThreatModel_NonExistentDependencyIsSecure` | 20 | Safe failure mode |
| `TestThreatModel_CascadingFailure` | 44 | Failure propagation |
| `TestThreatModel_TopologicalSortPreventsEarlyExecution` | 45 | Order enforcement |
| `TestThreatModel_InterfaceBasedDetectionPreventsTypeSpoofing` | 48 | Type safety |
| **Total** | **554 lines** | **11 threat categories** |

## Attack Scenarios Tested

### Scenario 1: Compromised Build Step
```
Attacker compromises build step → Verification fails → Test step blocked
✅ PREVENTED: Unverified data isolation
```

### Scenario 2: Circular Policy Injection
```
Attacker injects policy: build→test→build → Cycle detected at load time
✅ PREVENTED: Circular dependency detection
```

### Scenario 3: Dependency Skipping
```
Attacker tries to skip build, go directly to test → Missing dep error
✅ PREVENTED: Missing dependency check
```

### Scenario 4: Unauthorized Data Access
```
Test step tries to access audit data without declaring dependency
✅ PREVENTED: Data isolation enforcement
```

### Scenario 5: Type Confusion
```
Attacker creates fake "product" attestation without Producer interface
✅ PREVENTED: Interface-based type detection
```

## Verification

Run the threat model tests:

```bash
go test -v ./policy -run TestThreatModel
```

All 11 tests must pass to ensure the security guarantees are maintained.

## Conclusion

The cross-step attestation access feature implements defense-in-depth with multiple layers:

1. **Policy Load Time**: Circular dependency detection
2. **Verification Time**: Topological sort, dependency checking
3. **Evaluation Time**: Data isolation, interface-based detection
4. **Failure Mode**: Cascade failures, safe defaults

The comprehensive test suite validates all threat categories and ensures the security model is robust against known attacks.
