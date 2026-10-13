#!/usr/bin/env bash
# =============================================================================
# Codé — TLS Certificate Generation Script
# =============================================================================
#
# Generates a complete PKI hierarchy for the lab environment:
#   1. Root Certificate Authority (CA)
#   2. Server certificate (for Team Server, signed by CA)
#   3. Client certificate (for Operator Console mTLS, signed by CA)
#
# All certificates are scoped to the lab subnet 10.13.37.0/24.
#
# Usage:
#   chmod +x generate_certs.sh
#   ./generate_certs.sh
#
# Output structure:
#   ca/
#     ca.key          — CA private key
#     ca.crt          — CA certificate (self-signed)
#   server/
#     server.key      — Server private key
#     server.csr      — Server certificate signing request
#     server.crt      — Server certificate (signed by CA)
#   client/
#     client.key      — Client private key
#     client.csr      — Client certificate signing request
#     client.crt      — Client certificate (signed by CA)
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Lab network settings
SERVER_IP="${SERVER_IP:-10.13.37.1}"
LAB_SUBNET="10.13.37.0/24"

# Certificate validity
CA_DAYS="${CA_DAYS:-3650}"          # CA valid for 10 years
CERT_DAYS="${CERT_DAYS:-365}"      # Server/client certs valid for 1 year

# Key sizes
KEY_SIZE="${KEY_SIZE:-4096}"        # RSA key size in bits

# Output directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_DIR="${SCRIPT_DIR}/ca"
SERVER_DIR="${SCRIPT_DIR}/server"
CLIENT_DIR="${SCRIPT_DIR}/client"

# Distinguished Name fields
DN_COUNTRY="${DN_COUNTRY:-US}"
DN_STATE="${DN_STATE:-Lab}"
DN_LOCALITY="${DN_LOCALITY:-Lab}"
DN_ORG="${DN_ORG:-Code Academic C2}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_openssl() {
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL is not installed or not in PATH."
        echo "Install it with:"
        echo "  Ubuntu/Debian: sudo apt-get install openssl"
        echo "  macOS:         brew install openssl"
        echo "  RHEL/CentOS:   sudo yum install openssl"
        exit 1
    fi
    local version
    version=$(openssl version)
    log_info "Using: ${version}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo "=============================================="
    echo "  Codé — TLS Certificate Generator"
    echo "=============================================="
    echo ""
    echo "  Server IP:     ${SERVER_IP}"
    echo "  Lab Subnet:    ${LAB_SUBNET}"
    echo "  CA Validity:   ${CA_DAYS} days"
    echo "  Cert Validity: ${CERT_DAYS} days"
    echo "  Key Size:      ${KEY_SIZE} bits"
    echo ""

    check_openssl

    # -----------------------------------------------------------------------
    # Warn if output directories exist
    # -----------------------------------------------------------------------
    if [[ -d "${CA_DIR}" ]] || [[ -d "${SERVER_DIR}" ]] || [[ -d "${CLIENT_DIR}" ]]; then
        log_warn "Existing certificate directories found."
        read -p "Overwrite? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Aborted."
            exit 0
        fi
    fi

    # Create output directories
    mkdir -p "${CA_DIR}" "${SERVER_DIR}" "${CLIENT_DIR}"

    # -----------------------------------------------------------------------
    # Step 1: Generate Root CA
    # -----------------------------------------------------------------------
    log_info "Step 1/3: Generating Root Certificate Authority..."

    # Generate CA private key
    openssl genrsa -out "${CA_DIR}/ca.key" "${KEY_SIZE}" 2>/dev/null
    chmod 600 "${CA_DIR}/ca.key"

    # Generate self-signed CA certificate
    openssl req -x509 -new -nodes \
        -key "${CA_DIR}/ca.key" \
        -sha256 \
        -days "${CA_DAYS}" \
        -out "${CA_DIR}/ca.crt" \
        -subj "/C=${DN_COUNTRY}/ST=${DN_STATE}/L=${DN_LOCALITY}/O=${DN_ORG}/CN=Code Lab CA"

    log_info "  CA key:  ${CA_DIR}/ca.key"
    log_info "  CA cert: ${CA_DIR}/ca.crt"

    # -----------------------------------------------------------------------
    # Step 2: Generate Server Certificate
    # -----------------------------------------------------------------------
    log_info "Step 2/3: Generating Server certificate..."

    # Create server extensions config
    cat > "${SERVER_DIR}/server_ext.cnf" <<EOF
[req]
default_bits = ${KEY_SIZE}
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
C  = ${DN_COUNTRY}
ST = ${DN_STATE}
L  = ${DN_LOCALITY}
O  = ${DN_ORG}
CN = Code Team Server

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
# Primary server IP
IP.1 = ${SERVER_IP}
# Additional lab IPs (common Team Server addresses)
IP.2 = 10.13.37.2
IP.3 = 10.13.37.3
IP.4 = 10.13.37.4
IP.5 = 10.13.37.5
# Localhost for development
IP.6 = 127.0.0.1
DNS.1 = localhost
DNS.2 = teamserver.lab
EOF

    # Generate server private key
    openssl genrsa -out "${SERVER_DIR}/server.key" "${KEY_SIZE}" 2>/dev/null
    chmod 600 "${SERVER_DIR}/server.key"

    # Generate server CSR
    openssl req -new \
        -key "${SERVER_DIR}/server.key" \
        -out "${SERVER_DIR}/server.csr" \
        -config "${SERVER_DIR}/server_ext.cnf"

    # Sign server certificate with CA
    openssl x509 -req \
        -in "${SERVER_DIR}/server.csr" \
        -CA "${CA_DIR}/ca.crt" \
        -CAkey "${CA_DIR}/ca.key" \
        -CAcreateserial \
        -out "${SERVER_DIR}/server.crt" \
        -days "${CERT_DAYS}" \
        -sha256 \
        -extensions v3_req \
        -extfile "${SERVER_DIR}/server_ext.cnf" \
        2>/dev/null

    log_info "  Server key:  ${SERVER_DIR}/server.key"
    log_info "  Server cert: ${SERVER_DIR}/server.crt"

    # -----------------------------------------------------------------------
    # Step 3: Generate Client Certificate (for mTLS)
    # -----------------------------------------------------------------------
    log_info "Step 3/3: Generating Client certificate (mTLS)..."

    # Create client extensions config
    cat > "${CLIENT_DIR}/client_ext.cnf" <<EOF
[req]
default_bits = ${KEY_SIZE}
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
C  = ${DN_COUNTRY}
ST = ${DN_STATE}
L  = ${DN_LOCALITY}
O  = ${DN_ORG}
CN = Code Operator

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

    # Generate client private key
    openssl genrsa -out "${CLIENT_DIR}/client.key" "${KEY_SIZE}" 2>/dev/null
    chmod 600 "${CLIENT_DIR}/client.key"

    # Generate client CSR
    openssl req -new \
        -key "${CLIENT_DIR}/client.key" \
        -out "${CLIENT_DIR}/client.csr" \
        -config "${CLIENT_DIR}/client_ext.cnf"

    # Sign client certificate with CA
    openssl x509 -req \
        -in "${CLIENT_DIR}/client.csr" \
        -CA "${CA_DIR}/ca.crt" \
        -CAkey "${CA_DIR}/ca.key" \
        -CAcreateserial \
        -out "${CLIENT_DIR}/client.crt" \
        -days "${CERT_DAYS}" \
        -sha256 \
        -extensions v3_req \
        -extfile "${CLIENT_DIR}/client_ext.cnf" \
        2>/dev/null

    log_info "  Client key:  ${CLIENT_DIR}/client.key"
    log_info "  Client cert: ${CLIENT_DIR}/client.crt"

    # -----------------------------------------------------------------------
    # Verification
    # -----------------------------------------------------------------------
    echo ""
    log_info "Verifying certificate chain..."

    # Verify server cert against CA
    if openssl verify -CAfile "${CA_DIR}/ca.crt" "${SERVER_DIR}/server.crt" > /dev/null 2>&1; then
        log_info "  ✓ Server certificate verified against CA"
    else
        log_error "  ✗ Server certificate verification FAILED"
        exit 1
    fi

    # Verify client cert against CA
    if openssl verify -CAfile "${CA_DIR}/ca.crt" "${CLIENT_DIR}/client.crt" > /dev/null 2>&1; then
        log_info "  ✓ Client certificate verified against CA"
    else
        log_error "  ✗ Client certificate verification FAILED"
        exit 1
    fi

    # -----------------------------------------------------------------------
    # Print certificate fingerprints (for agent pinning)
    # -----------------------------------------------------------------------
    echo ""
    log_info "Certificate fingerprints (for agent cert pinning):"
    echo ""

    SERVER_SHA256=$(openssl x509 -in "${SERVER_DIR}/server.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d'=' -f2)
    CA_SHA256=$(openssl x509 -in "${CA_DIR}/ca.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d'=' -f2)

    echo "  CA (SHA-256):     ${CA_SHA256}"
    echo "  Server (SHA-256): ${SERVER_SHA256}"
    echo ""
    echo "  Use the server fingerprint in the agent build:"
    echo "    make agent SERVER_CERT_SHA256=\"${SERVER_SHA256}\""
    echo ""

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    echo ""
    echo "=============================================="
    echo "  Certificate generation complete!"
    echo "=============================================="
    echo ""
    echo "  Files generated:"
    echo "    ${CA_DIR}/ca.key          — CA private key (KEEP SECRET)"
    echo "    ${CA_DIR}/ca.crt          — CA certificate"
    echo "    ${SERVER_DIR}/server.key  — Server private key (KEEP SECRET)"
    echo "    ${SERVER_DIR}/server.crt  — Server certificate"
    echo "    ${CLIENT_DIR}/client.key  — Client private key (KEEP SECRET)"
    echo "    ${CLIENT_DIR}/client.crt  — Client certificate"
    echo ""
    echo "  Usage:"
    echo "    Team Server:       --tls-cert server/server.crt --tls-key server/server.key --ca-cert ca/ca.crt"
    echo "    Operator Console:  --tls-cert client/client.crt --tls-key client/client.key --ca-cert ca/ca.crt"
    echo "    Agent build:       Embed ca.crt and pin server.crt fingerprint at compile time"
    echo ""
    echo "  ⚠  NEVER commit private keys (.key files) to version control!"
    echo ""
}

main "$@"
