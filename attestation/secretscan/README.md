# Secret Scan Attestor

The secretscan attestor is a post-product attestor that scans attestations and products for secrets and other sensitive information. It helps prevent accidental secret leakage by detecting secrets and securely storing their cryptographic digests instead of the actual values.

## How It Works

The attestor uses [Gitleaks](https://github.com/zricethezav/gitleaks) to scan for secrets in:

1. Products generated during the attestation process
2. Attestations from other attestors that ran earlier in the pipeline
3. Environment variable values that match sensitive patterns:
   - Values of currently set environment variables that match sensitive patterns
   - Respects the user-defined sensitive environment variable configuration from the attestation context

When secrets are found, they are recorded in a structured format with the actual secret replaced by a DigestSet containing cryptographic hashes of the secret using all configured hash algorithms from the attestation context.

The attestor enhances Gitleaks' default rule set with custom rules based on the environment variables considered sensitive. By default, it uses the `DefaultSensitiveEnvList` from the environment package, which includes both explicit variable names (like `AWS_SECRET_ACCESS_KEY`) and glob patterns (like `*TOKEN*`, `*SECRET*`, `*PASSWORD*`). It also respects any customizations made to the sensitive environment variable list through the attestation context's environment capturer options.

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `fail-on-detection` | `false` | If true, the attestation process will fail if secrets are detected |
| `max-file-size-mb` | `10` | Maximum file size in MB to scan (prevents resource exhaustion) |
| `config-path` | `""` | Path to custom Gitleaks configuration file in TOML format |
| `allowlist-regex` | `""` | Regex pattern for content to ignore (can be specified multiple times) |
| `allowlist-stopword` | `""` | Specific string to ignore (can be specified multiple times) |

> **Important Note on Allowlists**: When `config-path` is provided, the `allowlist-regex` and `allowlist-stopword` options are ignored. All allowlisting must be defined within the Gitleaks TOML configuration file. The `max-file-size-mb` setting still applies and will override any value in the TOML configuration.

## Execution Order and Coverage

The secretscan attestor runs as a `PostProductRunType` attestor, which means it runs after all material, execute, and product attestors have completed.

**Important Notes on Coverage:**

1. **Attestation Coverage:** The attestor only scans attestations that have completed before it starts. This means:
   - It covers all pre-material, material, execute, and product attestors
   - It does NOT scan other post-product attestors that run concurrently with it
   - This limitation prevents race conditions and ensures reliable operation

2. **Product Coverage:** The attestor scans all products, regardless of which attestor created them.

3. **Binary Files:** By default, binary files and directories are automatically skipped to prevent false positives.

## Secret Representation

Secrets are represented as a DigestSet that contains multiple cryptographic hashes of the secret:

1. The set of hash algorithms is determined by the attestation context configuration
2. By default, this includes at minimum a SHA-256 hash
3. Each hash is stored as a hex-encoded string in the DigestSet map
4. This approach ensures the actual secret is never stored or transmitted

## Limitations

1. **Post-product Attestors:** As explained above, other post-product attestors are not scanned to avoid race conditions.

2. **Detection Capability:** The attestor relies on Gitleaks' detection rules, which primarily target common secret patterns like API keys, tokens, and credentials.

3. **Encoded Secrets:** The current implementation may not detect secrets that have been encoded (base64, etc.) or obfuscated.

## Examples

### Using Built-in Allowlist

```sh
witness run \
  --attestor secretscan \
  --secretscan-fail-on-detection=true \
  --secretscan-allowlist-regex="TEST_[A-Z0-9]+" \
  --workdir /path/to/repo
```

### Using Custom Gitleaks Configuration

```sh
witness run \
  --attestor secretscan \
  --secretscan-fail-on-detection=true \
  --secretscan-config-path="/path/to/custom-gitleaks.toml" \
  --workdir /path/to/repo
```

For a reference to the Gitleaks TOML configuration format, see the [Gitleaks documentation](https://github.com/zricethezav/gitleaks/blob/master/README.md).

## Implementation Details

The secretscan attestor includes these key features:

1. Secret detection based on Gitleaks' pattern matching
2. Secure cryptographic hashing of secrets with DigestSet
3. Configurable file size limits
4. Allowlisting capability for expected patterns
5. Location-based identification of where secrets were found

## Finding Format

The attestor produces findings in this format:

The `location` field clearly identifies where the secret was found:
- `product:/path/to/file.txt` - For secrets found in products
- `attestation:attestor-name` - For secrets found in attestations

```json
{
  "findings": [
    {
      "ruleId": "aws-access-key",
      "description": "AWS Access Key",
      "location": "product:/path/to/file.txt",
      "startLine": 10,
      "secret": {
        "SHA-256": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
      },
      "match": "AWS_ACCESS_KEY=AKI...",
      "entropy": 5.6
    }
  ]
}
```