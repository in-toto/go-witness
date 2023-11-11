#!/bin/bash

go build -o witnesslib.so -buildmode=c-shared lib/main.go

# Define paths for keys, certificates, and Go shared library
KEYS_CERTS_DIR="keys_and_certs"
PRIVATE_KEY_PATH="$KEYS_CERTS_DIR/private_key.pem"
CERTIFICATE_PATH="$KEYS_CERTS_DIR/certificate.pem"
GO_LIB_PATH="./witnesslib.so" # Adjust this path as needed

# Create directory for keys and certificates
mkdir -p $KEYS_CERTS_DIR

echo "Generating Private Key..."
openssl genrsa -out $PRIVATE_KEY_PATH 2048

echo "Generating Self-Signed Certificate..."
openssl req -new -x509 -key $PRIVATE_KEY_PATH -out $CERTIFICATE_PATH -days 365 -subj "/C=US/ST=California/L=San Francisco/O=TestifySec/OU=IT Department/CN=example.com"

# Running the Python test
echo "Running Python SDK test..."
python3 - <<EOF
from witness_sdk import WitnessSDK

# Initialize the SDK with the path to the shared library
sdk = WitnessSDK('$GO_LIB_PATH')

# Run the test function
sdk.test_run()
EOF

echo "Test completed."
