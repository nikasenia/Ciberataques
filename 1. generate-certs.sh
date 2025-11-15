#!/bin/bash

# ==============================================================================
# Certificate Generation Script for vulnTLSServer Testing
# ==============================================================================
# This script generates 4 test certificates (cert1-cert4) plus a CA certificate
# All files are placed in the my_certs/ directory
#
# Requirements: openssl
# Usage: ./generate-certs.sh
# ==============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CERTS_DIR="my_certs"
CA_KEY="ca-key.pem"
CA_CERT="ca-cert.pem"
DAYS_CA=3650
DAYS_CERT1=180
DAYS_CERT2=365
DAYS_CERT3=365
DAYS_CERT4=365

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Certificate Generation Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Create certificates directory
echo -e "${YELLOW}[1/10] Creating certificates directory...${NC}"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# ==============================================================================
# Step 1: Generate Certificate Authority (CA)
# ==============================================================================
if [ -f "$CA_KEY" ] && [ -f "$CA_CERT" ]; then
    echo -e "${BLUE}[2/10] CA certificate already exists, skipping...${NC}"
    echo -e "${BLUE}[3/10] CA certificate already exists, skipping...${NC}"
else
    echo -e "${YELLOW}[2/10] Generating CA private key (4096 bits)...${NC}"
    openssl genrsa -out "$CA_KEY" 4096 2>/dev/null

    echo -e "${YELLOW}[3/10] Generating CA certificate (valid for 10 years)...${NC}"
    openssl req -new -x509 -days $DAYS_CA -key "$CA_KEY" -out "$CA_CERT" \
      -subj "/C=ES/ST=Malaga/L=Huelin/O=BoqueronCA/CN=my trusted boqueron ca" 2>/dev/null

    echo -e "${GREEN}✓ CA certificate created successfully${NC}"
fi
echo ""

# ==============================================================================
# Certificate 1: Baseline "Good" Certificate (RSA 2048, 180 days)
# ==============================================================================
if [ -f "cert1-key.pem" ] && [ -f "cert1-cert.pem" ]; then
    echo -e "${BLUE}[4/10] cert1 already exists, skipping...${NC}"
else
    echo -e "${YELLOW}[4/10] Generating cert1 (Baseline Good - RSA 2048)...${NC}"

    # Generate private key
    openssl genrsa -out cert1-key.pem 2048 2>/dev/null

    # Create CSR
    openssl req -new -key cert1-key.pem -out cert1.csr \
      -subj "/C=ES/ST=Malaga/L=Huelin/O=BoqueronSL/CN=secure.boqueron.com" 2>/dev/null

    # Create SAN extension file
    cat > cert1-san.ext << EOF
subjectAltName = DNS:secure.example.com,DNS:www.secure.example.com
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

    # Sign certificate
    openssl x509 -req -in cert1.csr -CA "$CA_CERT" -CAkey "$CA_KEY" \
      -CAcreateserial -out cert1-cert.pem -days $DAYS_CERT1 \
      -extfile cert1-san.ext 2>/dev/null

    echo -e "${GREEN}✓ cert1 created (RSA 2048, 180 days, CA-signed)${NC}"
fi
echo ""

# ==============================================================================
# Certificate 2: Weak Key (RSA 1024)
# ==============================================================================
if [ -f "cert2-key.pem" ] && [ -f "cert2-cert.pem" ]; then
    echo -e "${BLUE}[5/10] cert2 already exists, skipping...${NC}"
else
    echo -e "${YELLOW}[5/10] Generating cert2 (Weak Key - RSA 1024)...${NC}"

    # Generate weak private key (1024 bits)
    openssl genrsa -out cert2-key.pem 1024 2>/dev/null

    # Create CSR
    openssl req -new -key cert2-key.pem -out cert2.csr \
      -subj "/C=ES/ST=Malaga/L=Huelin/O=WeakBoqueron/CN=weak.boqueron.com" 2>/dev/null

    # Create SAN extension file
    cat > cert2-san.ext << EOF
subjectAltName = DNS:weak.example.com
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

    # Sign certificate
    openssl x509 -req -in cert2.csr -CA "$CA_CERT" -CAkey "$CA_KEY" \
      -CAcreateserial -out cert2-cert.pem -days $DAYS_CERT2 \
      -extfile cert2-san.ext 2>/dev/null

    echo -e "${GREEN}✓ cert2 created (RSA 1024 - WEAK, 365 days, CA-signed)${NC}"
fi
echo ""

# ==============================================================================
# Certificate 3: Self-Signed with Misconfigurations
# ==============================================================================
if [ -f "cert3-key.pem" ] && [ -f "cert3-cert.pem" ]; then
    echo -e "${BLUE}[6/10] cert3 already exists, skipping...${NC}"
else
    echo -e "${YELLOW}[6/10] Generating cert3 (Self-Signed with IP/non-qualified hostname)...${NC}"

    # Generate private key
    openssl genrsa -out cert3-key.pem 2048 2>/dev/null

    # Create self-signed certificate with IP and non-qualified hostname
    openssl req -new -x509 -key cert3-key.pem -out cert3-cert.pem -days $DAYS_CERT3 \
      -subj "/C=ES/ST=Malaga/L=Huelin/O=SelfSignedEspeto/CN=192.168.1.100" \
      -addext "subjectAltName = DNS:server,IP:192.168.1.100" 2>/dev/null

    echo -e "${GREEN}✓ cert3 created (Self-signed, CN=IP, non-qualified hostname in SAN)${NC}"
fi
echo ""

# ==============================================================================
# Certificate 4: Wildcard Certificate (ECDSA P-256)
# ==============================================================================
if [ -f "cert4-key.pem" ] && [ -f "cert4-cert.pem" ]; then
    echo -e "${BLUE}[7/10] cert4 already exists, skipping...${NC}"
else
    echo -e "${YELLOW}[7/10] Generating cert4 (Wildcard - ECDSA P-256)...${NC}"

    # Generate ECDSA private key (P-256)
    openssl ecparam -name prime256v1 -genkey -out cert4-key.pem 2>/dev/null

    # Create CSR with wildcard
    openssl req -new -key cert4-key.pem -out cert4.csr \
      -subj "/C=ES/ST=Malaga/L=Huelin/O=WildcardBoqueron/CN=*.boqueron.org" 2>/dev/null

    # Create SAN extension file with wildcard
    cat > cert4-san.ext << EOF
subjectAltName = DNS:*.boqueron.org,DNS:boqueron.org
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
EOF

    # Sign certificate
    openssl x509 -req -in cert4.csr -CA "$CA_CERT" -CAkey "$CA_KEY" \
      -CAcreateserial -out cert4-cert.pem -days $DAYS_CERT4 \
      -extfile cert4-san.ext 2>/dev/null

    echo -e "${GREEN}✓ cert4 created (ECDSA P-256, wildcard *.example.org, CA-signed)${NC}"
fi
echo ""

# ==============================================================================
# Generate DH Parameters
# ==============================================================================
if [ -f "dhparams1024.pem" ]; then
    echo -e "${BLUE}[8/10] dhparams1024.pem already exists, skipping...${NC}"
else
    echo -e "${YELLOW}[8/10] Generating DH parameters (1024 bits - weak)...${NC}"
    openssl dhparam -out dhparams1024.pem 1024 2>/dev/null
    echo -e "${GREEN}✓ dhparams1024.pem created${NC}"
fi

if [ -f "dhparams2048.pem" ]; then
    echo -e "${BLUE}[9/10] dhparams2048.pem already exists, skipping...${NC}"
else
    echo -e "${YELLOW}[9/10] Generating DH parameters (2048 bits - strong)...${NC}"
    openssl dhparam -out dhparams2048.pem 2048 2>/dev/null
    echo -e "${GREEN}✓ dhparams2048.pem created${NC}"
fi
echo ""

# ==============================================================================
# Clean up intermediate files
# ==============================================================================
echo -e "${YELLOW}[10/10] Cleaning up intermediate files...${NC}"
rm -f *.csr *.ext *.srl
echo -e "${GREEN}✓ Cleanup complete${NC}"
echo ""

# ==============================================================================
# Verification and Summary
# ==============================================================================
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Certificate Generation Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}Generated files in ${CERTS_DIR}/:${NC}"
echo ""
echo -e "  ${BLUE}CA Files:${NC}"
echo -e "    - $CA_CERT (CA certificate)"
echo -e "    - $CA_KEY (CA private key)"
echo ""
echo -e "  ${BLUE}cert1 (Baseline Good):${NC}"
echo -e "    - cert1-cert.pem (RSA 2048, 180 days, CA-signed)"
echo -e "    - cert1-key.pem"
echo ""
echo -e "  ${BLUE}cert2 (Weak Key):${NC}"
echo -e "    - cert2-cert.pem (RSA 1024 - WEAK, 365 days, CA-signed)"
echo -e "    - cert2-key.pem"
echo ""
echo -e "  ${BLUE}cert3 (Self-Signed):${NC}"
echo -e "    - cert3-cert.pem (Self-signed, IP in CN, non-qualified hostname)"
echo -e "    - cert3-key.pem"
echo ""
echo -e "  ${BLUE}cert4 (Wildcard):${NC}"
echo -e "    - cert4-cert.pem (ECDSA P-256, wildcard *.example.org, CA-signed)"
echo -e "    - cert4-key.pem"
echo ""
echo -e "  ${BLUE}DH Parameters:${NC}"
echo -e "    - dhparams1024.pem (1024 bits - weak, for testing)"
echo -e "    - dhparams2048.pem (2048 bits - strong)"
echo ""

# Quick verification
echo -e "${YELLOW}Quick verification:${NC}"
echo ""
echo -e "cert1 (RSA 2048):"
openssl x509 -in cert1-cert.pem -noout -subject -issuer -dates | sed 's/^/  /'
echo ""
echo -e "cert2 (RSA 1024 - WEAK):"
openssl x509 -in cert2-cert.pem -noout -subject -issuer -dates | sed 's/^/  /'
echo ""
echo -e "cert3 (Self-signed):"
openssl x509 -in cert3-cert.pem -noout -subject -issuer -dates | sed 's/^/  /'
echo ""
echo -e "cert4 (ECDSA P-256, Wildcard):"
openssl x509 -in cert4-cert.pem -noout -subject -issuer -dates | sed 's/^/  /'
echo ""

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All certificates generated successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "  1. Run ${BLUE}./start.sh${NC} to start the Docker container"
echo -e "  2. Test with nmap: ${BLUE}sudo nmap -p 7001 --script vulnTLSServer 127.0.0.1${NC}"
echo ""
