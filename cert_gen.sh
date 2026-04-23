#!/usr/bin/env bash
# cert_gen.sh — Generate self-signed TLS certificate for development
# =================================================================
# Creates:
#   certs/server.key  – RSA 2048-bit private key
#   certs/server.crt  – Self-signed X.509 certificate (valid 365 days)
#
# Usage:
#   chmod +x cert_gen.sh
#   ./cert_gen.sh
#
# For production: replace with a cert signed by a trusted CA (e.g. Let's Encrypt)

set -euo pipefail

CERT_DIR="certs"
KEY_FILE="${CERT_DIR}/server.key"
CRT_FILE="${CERT_DIR}/server.crt"

mkdir -p "$CERT_DIR"

echo "[cert_gen] Generating RSA 2048-bit private key…"
openssl genrsa -out "$KEY_FILE" 2048

echo "[cert_gen] Generating self-signed certificate (365 days)…"
openssl req -new -x509 \
    -key "$KEY_FILE" \
    -out "$CRT_FILE" \
    -days 365 \
    -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=Jackfruit Lab/CN=localhost" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

echo ""
echo "[cert_gen] ✓  Done!"
echo "  Key : ${KEY_FILE}"
echo "  Cert: ${CRT_FILE}"
echo ""
echo "  Fingerprint:"
openssl x509 -noout -fingerprint -sha256 -in "$CRT_FILE"
