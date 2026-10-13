# Codé — TLS Certificates

> [!CAUTION]
> **Never commit private key files (`.key`) to version control.**
> The `.gitignore` is configured to exclude all generated certificate files.

## Overview

This directory contains the certificate generation script and (after running
it) the PKI hierarchy used by all Codé components:

```
certs/
├── generate_certs.sh       ← Run this to generate everything
├── README.md               ← This file
├── ca/
│   ├── ca.key              — Root CA private key (KEEP SECRET)
│   └── ca.crt              — Root CA certificate
├── server/
│   ├── server.key          — Team Server private key (KEEP SECRET)
│   ├── server.csr          — Server certificate signing request
│   ├── server.crt          — Server certificate (signed by CA)
│   └── server_ext.cnf      — OpenSSL extensions config
└── client/
    ├── client.key          — Operator Console private key (KEEP SECRET)
    ├── client.csr          — Client certificate signing request
    ├── client.crt          — Client certificate (signed by CA)
    └── client_ext.cnf      — OpenSSL extensions config
```

## Quick Start

```bash
# Generate all certificates
chmod +x generate_certs.sh
./generate_certs.sh

# Or via the top-level Makefile
cd .. && make certs
```

## Certificate Details

### Root CA

- **Subject**: `CN=Code Lab CA, O=Code Academic C2`
- **Validity**: 10 years (default)
- **Key Size**: RSA 4096-bit
- **Purpose**: Signs both server and client certificates

### Server Certificate

- **Subject**: `CN=Code Team Server, O=Code Academic C2`
- **Validity**: 1 year (default)
- **Key Usage**: Digital Signature, Key Encipherment
- **Extended Key Usage**: TLS Server Authentication (`serverAuth`)
- **Subject Alternative Names**:
  - `IP:10.13.37.1` (primary Team Server)
  - `IP:10.13.37.2` through `IP:10.13.37.5` (alternate lab IPs)
  - `IP:127.0.0.1` (localhost development)
  - `DNS:localhost`
  - `DNS:teamserver.lab`

### Client Certificate (Mutual TLS)

- **Subject**: `CN=Code Operator, O=Code Academic C2`
- **Validity**: 1 year (default)
- **Key Usage**: Digital Signature
- **Extended Key Usage**: TLS Client Authentication (`clientAuth`)
- **Purpose**: Authenticates the Operator Console to the Team Server's gRPC API

## Usage by Component

### Team Server

The Team Server uses the server certificate to accept TLS connections from
both agents and operators. It uses the CA certificate to verify operator
client certificates (mutual TLS on the gRPC port).

```bash
./serverd \
    --tls-cert  ../certs/server/server.crt \
    --tls-key   ../certs/server/server.key \
    --ca-cert   ../certs/ca/ca.crt \
    --listen    10.13.37.1:443
```

### Operator Console

The Operator Console presents its client certificate for mutual TLS
authentication when connecting to the Team Server's gRPC API.

```bash
./console \
    --tls-cert  ../certs/client/client.crt \
    --tls-key   ../certs/client/client.key \
    --ca-cert   ../certs/ca/ca.crt \
    --server    10.13.37.1:50051
```

### Agent

The agent does **not** use the system trust store. Instead:

1. The **CA certificate** (`ca.crt`) is embedded into the agent binary at
   compile time.
2. The **server certificate fingerprint** (SHA-256) is pinned at compile time.
3. At runtime, the agent verifies the server's certificate chain against the
   embedded CA and checks the fingerprint against the pinned hash.

```bash
# The generate_certs.sh script prints the fingerprint:
#   Server (SHA-256): AA:BB:CC:...

# Pass it to the agent build:
make agent SERVER_CERT_SHA256="AA:BB:CC:..."
```

## Customization

The generation script accepts environment variables:

| Variable | Default | Description |
|---|---|---|
| `SERVER_IP` | `10.13.37.1` | Primary Team Server IP address |
| `CA_DAYS` | `3650` | CA certificate validity (days) |
| `CERT_DAYS` | `365` | Server/client certificate validity (days) |
| `KEY_SIZE` | `4096` | RSA key size in bits |
| `DN_COUNTRY` | `US` | Distinguished Name: country |
| `DN_STATE` | `Lab` | Distinguished Name: state |
| `DN_LOCALITY` | `Lab` | Distinguished Name: locality |
| `DN_ORG` | `Code Academic C2` | Distinguished Name: organization |

Example with custom settings:

```bash
SERVER_IP=10.13.37.100 CA_DAYS=730 CERT_DAYS=90 ./generate_certs.sh
```

## Security Notes

1. **Private keys** (`*.key`) must never leave the machine they were generated
   on. Transfer certificates (`.crt`) only.
2. In a real deployment, you would use separate key ceremonies and HSMs. This
   is a simplified lab setup.
3. The CA key is unencrypted for automation convenience. In production, protect
   it with a passphrase.
4. Certificate revocation (CRL/OCSP) is not implemented — this is a lab tool.
5. All certificates are scoped to the `10.13.37.0/24` lab subnet by design.
