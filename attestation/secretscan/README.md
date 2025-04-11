# Secret Scan Attestor

The secretscan attestor is a post-product attestor that scans attestations and products for secrets and other sensitive information. It helps prevent accidental secret leakage by detecting secrets and optionally sanitizing them in attestation outputs.

## How It Works

The attestor uses [Gitleaks](https://github.com/zricethezav/gitleaks) to scan for secrets in:

1. Products generated during the attestation process
2. Attestations from other attestors that ran earlier in the pipeline

When secrets are found, they are recorded in a structured format with the actual secret obfuscated for security. Optionally, the attestor can sanitize attestations by replacing secrets with redaction markers.

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `fail-on-detection` | `false` | If true, the attestation process will fail if secrets are detected |
| `max-file-size-mb` | `10` | Maximum file size in MB to scan (prevents resource exhaustion) |
| `config-path` | `""` | Path to custom Gitleaks configuration file (not currently implemented) |
| `allowlist-regex` | `""` | Regex pattern for content to ignore (can be specified multiple times) |
| `allowlist-stopword` | `""` | Specific string to ignore (can be specified multiple times) |
| `sanitize-attestations` | `true` | Sanitize attestations by replacing secrets with redaction markers |

## Execution Order and Coverage

The secretscan attestor runs as a `PostProductRunType` attestor, which means it runs after all material, execute, and product attestors have completed.

**Important Notes on Coverage:**

1. **Attestation Coverage:** The attestor only scans attestations that have completed before it starts. This means:
   - It covers all pre-material, material, execute, and product attestors
   - It does NOT scan other post-product attestors that run concurrently with it
   - This limitation prevents race conditions and ensures reliable operation

2. **Product Coverage:** The attestor scans all products, regardless of which attestor created them.

3. **Binary Files:** By default, binary files and directories are automatically skipped to prevent false positives.

## Sanitization Behavior

When `sanitize-attestations` is enabled (the default):

1. Secrets detected in attestations are replaced with redaction markers during JSON serialization
2. The markers include the rule ID and a deterministic finding ID for cross-referencing
3. This sanitization is applied only when attestations are serialized to JSON
4. Sanitization is not applied to other post-product attestors

Example redaction format: `[REDACTED:aws-access-key:a1b2c3d4e5]`

## Limitations

1. **Post-product Attestors:** As explained above, other post-product attestors are not scanned to avoid race conditions.

2. **Detection Capability:** The attestor relies on Gitleaks' detection rules, which primarily target common secret patterns like API keys, tokens, and credentials.

3. **Encoded Secrets:** The current implementation may not detect secrets that have been encoded (base64, etc.) or obfuscated.

## Example

```sh
witness run \
  --attestor secretscan \
  --secretscan-fail-on-detection=true \
  --secretscan-allowlist-regex="TEST_[A-Z0-9]+" \
  --secretscan-sanitize-attestations=true \
  --workdir /path/to/repo
```

## Implementation Details

The secretscan attestor includes these key features:

1. Secret detection based on Gitleaks' pattern matching
2. JSON sanitization for attestation outputs
3. Configurable file size limits
4. Allowlisting capability for expected patterns
5. Deterministic finding IDs for cross-referencing between findings and redactions
6. Source-based file paths for improved identification of where secrets were found

## Finding Format

The attestor produces findings in this format:

Note that the `file` field now uses the same format as the `source` field to clearly identify where the secret was found:
- `product:/path/to/file.txt` - For secrets found in products
- `attestation:attestor-name` - For secrets found in attestations

```json
{
  "findings": [
    {
      "ruleId": "aws-access-key",
      "description": "AWS Access Key",
      "file": "product:/path/to/file.txt",
      "startLine": 10,
      "secret": "aws-access-key:AKI...:SHA256:a1b2c3d4...",
      "match": "AWS_ACCESS_KEY=AKI...",
      "source": "product:/path/to/file.txt"
    }
  ],
  "sanitization_report": {
    "attestations_sanitized": 1,
    "findings": {
      "a1b2c3d4e5": {
        "id": "a1b2c3d4e5",
        "rule_id": "aws-access-key",
        "description": "AWS Access Key",
        "file": "product:/path/to/file.txt",
        "line": 10,
        "source": "product:/path/to/file.txt"
      }
    }
  }
}
```