#!/bin/bash

# ==============================================================================
# Docker Apache Container Startup Script
# ==============================================================================
# This script:
#   1. Loads the tc_lab1_apache.tar Docker image
#   2. Stops and removes any existing tc_lab1 container
#   3. Runs the container with all required ports
#   4. Copies the my_certs directory and ssl-config.conf to the container
#   5. Enables SSL module and configures Apache
#   6. Restarts Apache
#
# Requirements: 
#   - Docker installed
#   - tc_lab1_apache.tar in ~/Downloads
#   - my_certs/ directory with certificates
#   - ssl-config.conf file
#
# Usage: ./start.sh
# ==============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_TAR="tc_lab1_apache.tar"
IMAGE_NAME="tc_lab1_apache:latest"
CONTAINER_NAME="tc_lab1"
CERTS_DIR="my_certs"
SSL_CONFIG="ssl-config.conf"

# Container paths
CONTAINER_CERTS_DIR="/etc/ssl/my_certs"
CONTAINER_APACHE_CONF="/etc/apache2/sites-enabled/my_ssl.conf"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Docker Apache Container Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# ==============================================================================
# Step 1: Check prerequisites
# ==============================================================================
echo -e "${YELLOW}[1/9] Checking prerequisites...${NC}"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    exit 1
fi

# Check if image tar exists
if [ ! -f "$IMAGE_TAR" ]; then
    echo -e "${RED}Error: Docker image tar not found at $IMAGE_TAR${NC}"
    echo -e "${YELLOW}Please ensure tc_lab1_apache.tar is in ~/Downloads/${NC}"
    exit 1
fi

# Check if certificates directory exists
if [ ! -d "$CERTS_DIR" ]; then
    echo -e "${RED}Error: Certificates directory '$CERTS_DIR' not found${NC}"
    echo -e "${YELLOW}Please run ./generate-certs.sh first${NC}"
    exit 1
fi

# Check if SSL config file exists
if [ ! -f "$SSL_CONFIG" ]; then
    echo -e "${RED}Error: SSL configuration file '$SSL_CONFIG' not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ All prerequisites met${NC}"
echo ""

# ==============================================================================
# Step 2: Load Docker image
# ==============================================================================
echo -e "${YELLOW}[2/9] Loading Docker image from tar...${NC}"

# Check if image already exists
if docker image inspect "$IMAGE_NAME" &> /dev/null; then
    echo -e "${BLUE}Image $IMAGE_NAME already exists, skipping load${NC}"
else
    docker load -i "$IMAGE_TAR"
    echo -e "${GREEN}✓ Docker image loaded successfully${NC}"
fi
echo ""

# ==============================================================================
# Step 3: Stop and remove existing container
# ==============================================================================
echo -e "${YELLOW}[3/9] Checking for existing container...${NC}"

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${BLUE}Stopping and removing existing container '$CONTAINER_NAME'...${NC}"
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
    echo -e "${GREEN}✓ Existing container removed${NC}"
else
    echo -e "${BLUE}No existing container found${NC}"
fi
echo ""

# ==============================================================================
# Step 4: Run Docker container with all ports
# ==============================================================================
echo -e "${YELLOW}[4/9] Starting Docker container with all ports...${NC}"

docker run -d --name "$CONTAINER_NAME" --restart always \
  -p 8888:80 \
  -p 8443:443 \
  -p 9443:9443 \
  -p 7001:7001 \
  -p 7002:7002 \
  -p 7003:7003 \
  -p 7004:7004 \
  "$IMAGE_NAME"

echo -e "${GREEN}✓ Container started successfully${NC}"
echo ""

# Wait for container to be fully started
echo -e "${YELLOW}[5/9] Waiting for container to initialize...${NC}"
sleep 3
echo -e "${GREEN}✓ Container initialized${NC}"
echo ""

# ==============================================================================
# Step 5: Create certificates directory in container
# ==============================================================================
echo -e "${YELLOW}[6/9] Creating certificates directory in container...${NC}"

docker exec "$CONTAINER_NAME" mkdir -p "$CONTAINER_CERTS_DIR"
docker exec "$CONTAINER_NAME" chmod 755 "$CONTAINER_CERTS_DIR"

echo -e "${GREEN}✓ Certificates directory created${NC}"
echo ""

# ==============================================================================
# Step 6: Copy certificates to container
# ==============================================================================
echo -e "${YELLOW}[7/9] Copying certificates to container...${NC}"

# Copy entire my_certs directory
docker cp "$CERTS_DIR/." "$CONTAINER_NAME:$CONTAINER_CERTS_DIR/"

# Set proper permissions (use shell -c for wildcard expansion)
docker exec "$CONTAINER_NAME" sh -c "chmod 644 $CONTAINER_CERTS_DIR/*.pem"
docker exec "$CONTAINER_NAME" sh -c "chmod 600 $CONTAINER_CERTS_DIR/*-key.pem"
docker exec "$CONTAINER_NAME" chown -R root:root "$CONTAINER_CERTS_DIR"

echo -e "${GREEN}✓ Certificates copied and permissions set${NC}"
echo ""

# ==============================================================================
# Step 7: Copy SSL configuration to container
# ==============================================================================
echo -e "${YELLOW}[8/9] Copying SSL configuration to container...${NC}"

# Copy SSL config
docker cp "$SSL_CONFIG" "$CONTAINER_NAME:$CONTAINER_APACHE_CONF"

# Enable the SSL configuration
docker exec "$CONTAINER_NAME" a2ensite ssl-vhosts.conf 2>/dev/null || true

# Enable required Apache modules
docker exec "$CONTAINER_NAME" a2enmod ssl 2>/dev/null || true
docker exec "$CONTAINER_NAME" a2enmod headers 2>/dev/null || true
docker exec "$CONTAINER_NAME" a2enmod socache_shmcb 2>/dev/null || true

echo -e "${GREEN}✓ SSL configuration copied and enabled${NC}"
echo ""

# ==============================================================================
# Step 8: Test configuration and restart Apache
# ==============================================================================
echo -e "${YELLOW}[9/9] Testing Apache configuration and restarting...${NC}"

# Test configuration
if docker exec "$CONTAINER_NAME" apachectl configtest 2>&1 | grep -q "Syntax OK"; then
    echo -e "${GREEN}✓ Apache configuration is valid${NC}"
    
    # Restart Apache
    docker exec "$CONTAINER_NAME" apachectl restart
    echo -e "${GREEN}✓ Apache restarted successfully${NC}"
else
    echo -e "${RED}Warning: Apache configuration test failed${NC}"
    echo -e "${YELLOW}Attempting to restart anyway...${NC}"
    docker exec "$CONTAINER_NAME" apachectl restart || true
fi
echo ""

# ==============================================================================
# Summary and next steps
# ==============================================================================
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Container Setup Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}Container Status:${NC}"
docker ps --filter "name=$CONTAINER_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""
echo -e "${GREEN}Available Ports:${NC}"
echo -e "  ${BLUE}HTTP:${NC}"
echo -e "    - 8888  → http://localhost:8888"
echo ""
echo -e "  ${BLUE}HTTPS (Original VirtualHosts):${NC}"
echo -e "    - 8443  → https://localhost:8443 (tc.uc3m.es)"
echo -e "    - 9443  → https://localhost:9443 (internal.tc.uc3m.es)"
echo ""
echo -e "  ${BLUE}HTTPS (New Test VirtualHosts):${NC}"
echo -e "    - 7001  → cert1 (Baseline Good - RSA 2048)"
echo -e "    - 7002  → cert2 (Weak Key - RSA 1024 + Old TLS)"
echo -e "    - 7003  → cert3 (Self-Signed + Misconfigurations)"
echo -e "    - 7004  → cert4 (Wildcard - ECDSA P-256)"
echo ""
echo -e "  ${BLUE}# Check Apache logs inside container${NC}"
echo -e "  docker exec $CONTAINER_NAME tail -f /var/log/apache2/error.log"
echo ""
echo -e "  ${BLUE}# Access container shell${NC}"
echo -e "  docker exec -it $CONTAINER_NAME /bin/bash"
echo ""
echo -e "  ${BLUE}# Stop container${NC}"
echo -e "  docker stop $CONTAINER_NAME"
echo ""
echo -e "  ${BLUE}# Restart container${NC}"
echo -e "  docker restart $CONTAINER_NAME"
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Setup complete! Ready for testing.${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
