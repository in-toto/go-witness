# SecretScan Attestor Examples

This directory contains examples demonstrating the capabilities of the SecretScan attestor.

## Demo Scripts

### `demo-encoded-secrets.sh`

This script demonstrates the multi-layer encoding detection capabilities of the secretscan attestor. It:

1. Creates test files with secrets in various encodings:
   - Plain text
   - Base64-encoded
   - Double base64-encoded
   - URL-encoded
   - Hex-encoded
   - Mixed encoding (base64 + URL)

2. Runs the witness CLI with the secretscan attestor on each file

3. Extracts and displays the findings from each attestation

### Running the Demo

```sh
# Make sure the script is executable
chmod +x demo-encoded-secrets.sh

# Run the demo
./demo-encoded-secrets.sh
```

## Additional Resources

For more information about the secretscan attestor, see the [main README](../README.md) in the parent directory.