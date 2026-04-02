#!/bin/bash
# =============================================================================
# Generate self-signed TLS certificates for development
# =============================================================================
# Usage: ./scripts/generate_tls_certs.sh [output_dir]
#
# This creates a self-signed certificate for local development.
# For production, use Let's Encrypt or a proper CA.
# =============================================================================

OUTPUT_DIR="${1:-./nginx/ssl}"

mkdir -p "$OUTPUT_DIR"

echo "Generating self-signed TLS certificate..."

openssl req -x509 \
    -newkey rsa:4096 \
    -keyout "$OUTPUT_DIR/server.key" \
    -out "$OUTPUT_DIR/server.crt" \
    -days 365 \
    -nodes \
    -subj "/C=US/ST=State/L=City/O=WAF/OU=Dev/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

# Generate DH parameters (optional, for DHE cipher suites)
echo "Generating DH parameters (this may take a minute)..."
openssl dhparam -out "$OUTPUT_DIR/dhparam.pem" 2048

echo ""
echo "Certificates generated in: $OUTPUT_DIR"
echo "  - server.crt  (self-signed certificate)"
echo "  - server.key  (private key)"
echo "  - dhparam.pem (DH parameters)"
echo ""
echo "WARNING: These are self-signed certificates for development only."
echo "For production, use Let's Encrypt or a proper Certificate Authority."
