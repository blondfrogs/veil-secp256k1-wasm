#!/bin/bash
# Publish WASM package to npm

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "📦 Publishing WASM Package to npm..."
echo ""

# Check if logged in to npm
if ! npm whoami &> /dev/null; then
    echo -e "${RED}❌ Not logged in to npm!${NC}"
    echo "Please run: npm login"
    exit 1
fi

NPM_USER=$(npm whoami)
echo -e "${GREEN}✓ Logged in as: ${NPM_USER}${NC}"
echo ""

# Get version from Cargo.toml
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
echo -e "${YELLOW}Publishing version: ${VERSION}${NC}"
echo ""

# Confirm publication
read -p "Publish @${NPM_USER}/secp256k1-wasm@${VERSION} to npm? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Publication cancelled."
    exit 0
fi

# Build WASM package
echo ""
echo -e "${YELLOW}Building WASM package...${NC}"
./build.sh

# Publish to npm
echo ""
echo -e "${YELLOW}Publishing to npm...${NC}"
cd veil-wasm/pkg
npm publish --access public

echo ""
echo -e "${GREEN}✓ Successfully published @${NPM_USER}/secp256k1-wasm@${VERSION}!${NC}"
echo ""
echo "📦 View on npm: https://www.npmjs.com/package/@${NPM_USER}/secp256k1-wasm"
echo ""
echo "📥 Install with: npm install @${NPM_USER}/secp256k1-wasm"
echo ""
echo -e "${GREEN}🎉 Done!${NC}"
