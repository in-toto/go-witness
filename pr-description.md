## Summary

This PR adds documentation infrastructure to go-witness packages and attestors to enable rich, structured documentation generation:

- 📖 **Documentation Interface**: New `Documenter` interface for attestors to provide structured documentation
- 🏷️ **JSONSchema Tags**: Added descriptive jsonschema tags to structs across core packages
- 📝 **Package Documentation**: New documentation.go files for core packages with examples and usage
- 🔍 **Enhanced Attestor Metadata**: All attestors now implement Documentation() method with summaries, usage, and examples

## Changes

### Core Changes
- `attestation/documentation.go` - Defines Documenter interface and Documentation struct
- Added `Documentation()` method to all 25 attestors with:
  - Summary descriptions
  - Usage scenarios (when to use)
  - Realistic command examples

### JSONSchema Enhancements
Added descriptive tags to key structs:
- **cryptoutil**: DigestSet, DigestValue with hash algorithms and format descriptions
- **policy**: Policy, Step, Functionary, CertConstraint with field explanations
- **signer**: FileSignerProvider, KMSSignerProvider with configuration options
- **dsse**: Envelope, Signature with DSSE spec details
- **archivista**: Client with connection parameters

### Package Documentation
Created documentation.go files for:
- cryptoutil - Cryptographic utilities documentation
- policy - Policy engine documentation  
- signer - Signing provider framework docs
- dsse - DSSE envelope documentation
- archivista - Client library documentation

## Benefits

1. **Better Developer Experience**
   - IDE tooltips show field descriptions from jsonschema tags
   - Generated documentation includes rich descriptions
   - CLI tools can display attestor help

2. **Maintainable Documentation**
   - Documentation lives with code
   - Single source of truth
   - Easy to keep updated

3. **Extensible Framework**
   - New attestors automatically get documentation support
   - Consistent documentation structure
   - Machine-readable format for various outputs

## Testing

```bash
# Test that attestors implement Documenter
go test ./attestation/...

# Verify jsonschema generation
go run -tags jsonschema ./internal/test/jsonschema/main.go
```

## Related PRs
- Companion PR in witness repository uses these interfaces for enhanced CLI and docgen

## Future Work
- Add validation for documentation completeness
- Generate OpenAPI specs from jsonschema tags
- Create interactive documentation tools