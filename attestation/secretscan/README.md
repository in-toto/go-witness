# Secret Scan Attestor

The secretscan attestor is a post-product attestor that scans attestations and products for secrets and other sensitive information. It helps prevent accidental secret leakage by detecting secrets and securely storing their cryptographic digests instead of the actual values.

## How It Works

The attestor uses [Gitleaks](https://github.com/zricethezav/gitleaks) to scan for secrets in:

1. Products generated during the attestation process
2. Attestations from other attestors that ran earlier in the pipeline
3. Environment variable values that match sensitive patterns:
   - Scans for actual values of sensitive environment variables that might have leaked into files or attestations
   - Checks both for direct values and encoded values of environment variables
   - Supports partial matching of sensitive environment variable values
   - Respects the user-defined sensitive environment variable configuration from the attestation context
4. Multi-layer encoded secrets:
   - Detects secrets hidden in base64, hex, or URL-encoded content
   - Can decode multiple layers of encoding (e.g., double base64-encoded secrets)
   - Tracks the encoding path for audit and forensic purposes

When secrets are found, they are recorded in a structured format with the actual secret replaced by a DigestSet containing cryptographic hashes of the secret using all configured hash algorithms from the attestation context.

### Workflow Diagram

The following sequence diagram illustrates how the secretscan attestor works:

```mermaid
sequenceDiagram
    participant User
    participant Witness
    participant SecretScan
    participant Detector
    participant Scanner
    participant EnvScanner
    participant Decoder
    
    User->>Witness: Run with secretscan attestor
    Witness->>SecretScan: Initialize attestor
    SecretScan->>SecretScan: Load configuration
    Note over SecretScan: Configure allowlists, file limits, etc.
    
    Witness->>SecretScan: Run attestation
    
    SecretScan->>Detector: Initialize with patterns
    Note over Detector: Gitleaks pattern matching
    
    par Scan Products
        SecretScan->>Scanner: Scan product files
        Scanner->>Detector: Match patterns
        Scanner->>Decoder: Check for encoded content
        Decoder-->>Scanner: Return decoded secrets
        Scanner-->>SecretScan: Return findings
    and Scan Attestations
        SecretScan->>Scanner: Scan attestation data
        Scanner->>Detector: Match patterns
        Scanner->>Decoder: Check for encoded content
        Decoder-->>Scanner: Return decoded secrets
        Scanner-->>SecretScan: Return findings
    and Scan Environment Variables
        SecretScan->>EnvScanner: Get all sensitive env vars
        Note over EnvScanner: Gets current env variable values
        EnvScanner->>Detector: Search for plain sensitive values
        loop For each encoding layer
            EnvScanner->>Decoder: Identify encoded content
            Decoder-->>EnvScanner: Return decoded content
            EnvScanner->>Detector: Search for sensitive values in decoded content
            EnvScanner->>Decoder: Recursively check for more encoding layers
            Note over Decoder: Up to max-decode-layers deep
        end
        EnvScanner-->>SecretScan: Return findings with encoding paths
    end
    
    SecretScan->>SecretScan: Process all findings
    Note over SecretScan: Create DigestSet for each secret
    
    alt Fail on Detection (--secretscan-fail-on-detection=true)
        SecretScan->>Witness: Return error with secret count
        Witness->>User: Exit with non-zero code
    else Continue (default behavior)
        SecretScan->>Witness: Return attestation with findings
        Witness-->>User: Return attestation results
    end
```

This diagram shows the major components and data flow of the secretscan attestor process.

The attestor enhances Gitleaks' default rule set with custom rules based on the environment variables considered sensitive. By default, it uses the `DefaultSensitiveEnvList` from the environment package, which includes both explicit variable names (like `AWS_SECRET_ACCESS_KEY`) and glob patterns (like `*TOKEN*`, `*SECRET*`, `*PASSWORD*`). It also respects any customizations made to the sensitive environment variable list through the attestation context's environment capturer options.

**Important:** The environment variable scanning specifically looks for the **values** of sensitive environment variables that might have leaked into files, attestations, or other content. This differs from traditional secret scanning, which typically looks for patterns that match known secret formats. By examining actual environment variable values, the attestor can detect real secrets that have leaked from your environment, whether in plain text form or through various encoding methods.

The scanning process examines:
1. **All product files** - Source code, config files, build artifacts, etc.
2. **Attestation data** - JSON representations of attestor results
3. **Command outputs** - Stdout/stderr from command run attestors
4. **Decoded content** - Content after decoding base64, hex, or URL encoding

For each location, it searches for the actual values of sensitive environment variables that are currently set during attestation. For example, if you have `AWS_SECRET_ACCESS_KEY=1234abcd` set in your environment, the attestor will look for the string `1234abcd` anywhere in the scanned content.

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `fail-on-detection` | `false` | If true, the attestation process will fail if secrets are detected |
| `max-file-size-mb` | `10` | Maximum file size in MB to scan (prevents resource exhaustion) |
| `config-path` | `""` | Path to custom Gitleaks configuration file in TOML format |
| `allowlist-regex` | `""` | Regex pattern for content to ignore (can be specified multiple times) |
| `allowlist-stopword` | `""` | Specific string to ignore (can be specified multiple times) |
| `max-decode-layers` | `3` | Maximum number of encoding layers to decode (prevents resource exhaustion) |

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

4. **Encoded Content:** The attestor will recursively decode content up to `max-decode-layers` deep to find hidden secrets, supporting:
   - Base64 encoding
   - Hex encoding
   - URL encoding
   - Multiple layers of the same or different encoding types

## Secret Representation

Secrets are represented as a DigestSet that contains multiple cryptographic hashes of the secret:

1. The set of hash algorithms is determined by the attestation context configuration
2. By default, this includes at minimum a SHA-256 hash
3. Each hash is stored as a hex-encoded string in the DigestSet map
4. This approach ensures the actual secret is never stored or transmitted

## Advanced Features

### Multi-layer Encoding Detection

The secretscan attestor can detect secrets that have been encoded multiple times:

1. **Encoding Detection**: Automatically identifies base64, hex, and URL-encoded content
2. **Recursive Decoding**: Recursively decodes content up to the configured maximum layers
3. **Encoding Path Tracking**: Records the sequence of encodings used to hide the secret
4. **Environment Variable Pattern Matching**: Detects encoded environment variable values

When an encoded secret is found, the attestor adds an `encodingPath` field to the finding that lists all the encoding layers detected, which is valuable for:

- Forensic analysis to understand how the secret was hidden
- Determining if the encoding was deliberate obfuscation
- Helping remediate the source of the secret leak

### Environment Variable Protection

The attestor provides enhanced environment variable protection:

1. **Direct Environment Variable Detection**: Scans for sensitive environment variable values directly exposed in:
   - All product files (source code, config files, build artifacts, etc.)
   - Attestation data from earlier attestors (e.g., command run outputs, git info)
   - Decoded content from encoded data
2. **Encoded Environment Variable Detection**: Detects environment variable values hidden through encoding
3. **Partial Value Matching**: Can detect partial matches of sensitive values (useful for truncated secrets)
4. **Custom Match Redaction**: Securely redacts sensitive values in match context displays
5. **Pattern Matching**: Supports both exact matches and pattern-based matching for variable names
6. **Value-based Detection**: Focuses on the actual values of variables rather than just their names
7. **DigestSet Creation**: Securely stores cryptographic hashes of values instead of the values themselves
8. **Extensive Coverage**: Uses a comprehensive list of sensitive environment variables:
   - Common cloud provider credentials (AWS, Azure, GCP)
   - API keys and tokens for popular services
   - Generic patterns like `*TOKEN*`, `*SECRET*`, `*PASSWORD*`
   - User-defined sensitive environment variables

**How Environment Variable Scanning Works:**

1. The attestor gets all environment variables currently set in the execution environment
2. It identifies which variables are sensitive using the configured sensitive variable list
3. For each sensitive environment variable, it:
   - Searches for its value in all product files
   - Searches for its value in all attestation data
   - Searches for its value in any decoded content from encoded data
4. It also examines command run attestor outputs (stdout/stderr) for sensitive values
5. All found sensitive values are recorded as findings with secure digests

**Encoded Environment Variable Detection:**

The attestor has a powerful capability to detect sensitive environment variable values even when they've been encoded:

1. **Multi-layer Encoding Detection:**
   - When scanning files and attestations, the attestor looks for encoded content (base64, hex, URL-encoded)
   - It recursively decodes this content up to the configured `max-decode-layers` (default: 3)
   - For each layer of decoded content, it searches for sensitive environment variable values

2. **Encoding Path Tracking:**
   - When an encoded secret is found, the attestor records the exact "encoding path" 
   - For example, if a secret was base64-encoded and then hex-encoded, the path would be `["hex", "base64"]`
   - This helps identify how secrets were obfuscated

3. **Partial Match Support:**
   - The attestor can detect partial matches of encoded environment variable values
   - This catches cases where only a portion of a secret was encoded
   - For example, detecting just the beginning of an API token that was partially encoded

4. **Context Awareness:**
   - Special handling for common patterns like newlines often introduced by `echo` commands
   - Recognition of encoding artifacts and padding characters

## Examples

### Basic Usage

```sh
witness run -a secretscan -k key.pem -s step-name
```

### Fail on Secret Detection

To make CI/CD pipelines fail when secrets are detected:

```sh
witness run -a secretscan --secretscan-fail-on-detection=true -k key.pem -s step-name
```

When `--secretscan-fail-on-detection=true` is specified, the command will exit with a non-zero exit code if any secrets are found. This is useful in CI/CD pipelines to prevent accidental deployment of code containing sensitive information.

### Using Built-in Allowlist

```sh
witness run -a secretscan \
  --secretscan-fail-on-detection=true \
  --secretscan-allowlist-regex="TEST_[A-Z0-9]+" \
  --secretscan-allowlist-stopword="EXAMPLE_API_KEY" \
  -k key.pem -s step-name
```

### Using Custom Gitleaks Configuration

```sh
witness run -a secretscan \
  --secretscan-config-path="/path/to/custom-gitleaks.toml" \
  -k key.pem -s step-name
```

### Configuring Encoding Detection

```sh
witness run -a secretscan \
  --secretscan-max-decode-layers=5 \
  -k key.pem -s step-name
```

For a reference to the Gitleaks TOML configuration format, see the [Gitleaks documentation](https://github.com/zricethezav/gitleaks/blob/master/README.md).

## Real-World Examples

### Detecting Plain Secrets

When a file contains a plaintext secret:

```
API_KEY=1234567890abcdef
```

The attestor will detect it and create a finding like:

```json
{
  "ruleId": "generic-api-key",
  "description": "API Key detected",
  "location": "product:/path/to/file.txt",
  "startLine": 10,
  "secret": {
    "SHA-256": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
  },
  "match": "API_KEY=123[REDACTED]",
  "entropy": 5.6
}
```

### Detecting Environment Variables

For environment variables:

```
GITHUB_TOKEN=ghp_012345678901234567890123456789
```

The attestor creates a specific finding:

```json
{
  "ruleId": "witness-env-value-GITHUB-TOKEN",
  "description": "Sensitive environment variable value detected: GITHUB_TOKEN",
  "location": "product:/path/to/file.txt",
  "startLine": 10,
  "secret": {
    "SHA-256": "5d0b11a2c18800ccab20d01a60a9e58c535cc7da7f4cf582ace05aca9c8757dd"
  },
  "match": "HUB_TOKEN=[SENSITIVE-VALUE]"
}
```

### Detecting Encoded Environment Variables

Suppose you have `GITHUB_TOKEN=ghp_012345678901234567890123456789` set in your environment, and a file contains:

```
# This is output from a build script
Encoded token: Z2hwXzAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OQ==
```

The attestor will:
1. Detect the base64-encoded content
2. Decode it to `ghp_012345678901234567890123456789`
3. Recognize this as the value of the sensitive `GITHUB_TOKEN` environment variable
4. Create a finding:

```json
{
  "ruleId": "witness-encoded-env-value-GITHUB-TOKEN",
  "description": "Encoded sensitive environment variable value detected: GITHUB_TOKEN",
  "location": "product:/path/to/file.txt",
  "startLine": 2,
  "secret": {
    "SHA-256": "5d0b11a2c18800ccab20d01a60a9e58c535cc7da7f4cf582ace05aca9c8757dd"
  },
  "match": "Encoded token: [REDACTED]",
  "encodingPath": ["base64"],
  "locationApproximate": true
}
```

For multi-layer encoded environment variables like a double base64-encoded GitHub token:

```
# This is deeply hidden 
WjJod1h6QXhNak0wTlRZM09Ea3dNVEl6TkRVMk56ZzVNREV5TXpRMU5qYzRPUT09
```

The attestor will recursively decode and detect it:

```json
{
  "ruleId": "witness-encoded-env-value-GITHUB-TOKEN",
  "description": "Encoded sensitive environment variable value detected: GITHUB_TOKEN",
  "location": "product:/path/to/file.txt", 
  "startLine": 2,
  "secret": {
    "SHA-256": "5d0b11a2c18800ccab20d01a60a9e58c535cc7da7f4cf582ace05aca9c8757dd"
  },
  "match": "# This is deeply hidden [REDACTED]",
  "encodingPath": ["base64", "base64"],
  "locationApproximate": true
}
```

### Detecting Encoded Secrets

When a file contains a base64-encoded GitHub token:

```
Z2hwXzAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OQ==
```

The attestor will detect and decode it:

```json
{
  "ruleId": "generic-api-key",
  "description": "Detected a Generic API Key",
  "location": "product:/path/to/file.txt",
  "startLine": 10,
  "secret": {
    "SHA-256": "5d0b11a2c18800ccab20d01a60a9e58c535cc7da7f4cf582ace05aca9c8757dd"
  },
  "match": "GITHUB_T...23456789",
  "entropy": 3.6889665,
  "encodingPath": [
    "base64"
  ],
  "locationApproximate": true
}
```

### Detecting Multi-layer Encoded Secrets

For a double base64-encoded GitHub token:

```
WjJod1h6QXhNak0wTlRZM09Ea3dNVEl6TkRVMk56ZzVNREV5TXpRMU5qYzRPUT09
```

The attestor will recursively decode and detect it:

```json
{
  "ruleId": "witness-encoded-env-value-GITHUB-TOKEN",
  "description": "Encoded sensitive environment variable value detected: GITHUB_TOKEN",
  "location": "attestation:command-run",
  "startLine": 1,
  "secret": {
    "SHA-256": "5d0b11a2c18800ccab20d01a60a9e58c535cc7da7f4cf582ace05aca9c8757dd"
  },
  "match": "HUB_TOKEN=[REDACTED]",
  "encodingPath": [
    "base64",
    "base64"
  ],
  "locationApproximate": true
}
```

## Implementation Details

The secretscan attestor includes these key features:

1. Secret detection based on Gitleaks' pattern matching
2. Secure cryptographic hashing of secrets with DigestSet
3. Multi-layer encoding detection and decoding
4. Environment variable value detection
5. Configurable file size limits and decoding depth
6. Allowlisting capability for expected patterns
7. Location-based identification of where secrets were found

## Finding Format

The attestor produces findings with the following fields:

| Field | Description |
|-------|-------------|
| `ruleId` | Identifier of the rule that triggered the finding |
| `description` | Human-readable description of the secret type |
| `location` | Where the secret was found (product path or attestation name) |
| `startLine` | Line number where the secret was found (if available) |
| `secret` | DigestSet containing cryptographic hashes of the secret |
| `match` | Redacted context around the detected secret |
| `entropy` | Entropy score of the secret (if calculated) |
| `encodingPath` | Array listing all encoding layers detected (if encoded) |
| `locationApproximate` | Boolean flag indicating if the location is approximate |

The `location` field clearly identifies where the secret was found:
- `product:/path/to/file.txt` - For secrets found in products
- `attestation:attestor-name` - For secrets found in attestations

## Internal Architecture

The secretscan attestor is organized into several logical components:

1. **Detector**: Integration with Gitleaks for pattern matching
2. **Scanner**: Core scanning logic for files and content
3. **EnvScan**: Specialized scanning for environment variable values
4. **Encoding**: Multi-layer encoding detection and decoding
5. **Allowlist**: Configuration and management of allowlisted content
6. **Findings**: Secure handling and reporting of detected secrets
7. **Config**: Configuration management and validation

This modular design ensures maintainability, testability, and extensibility as new secret detection capabilities are added.