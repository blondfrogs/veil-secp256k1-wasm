#!/bin/bash
# Publish veil-crypto crate to crates.io

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "📦 Publishing veil-crypto to crates.io..."
echo ""

# Get version from Cargo.toml
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
echo -e "${YELLOW}Publishing version: ${VERSION}${NC}"
echo ""

# Check if cargo login is needed
if ! cargo owner --list veil-crypto 2>/dev/null | grep -q "."; then
    echo -e "${YELLOW}⚠️  You may need to login to crates.io${NC}"
    echo "Run: cargo login YOUR_TOKEN"
    echo ""
fi

# Confirm publication
read -p "Publish veil-crypto@${VERSION} to crates.io? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Publication cancelled."
    exit 0
fi

# Run tests first
echo ""
echo -e "${YELLOW}Running tests...${NC}"
cd veil-crypto
cargo test

# Dry run
echo ""
echo -e "${YELLOW}Running dry-run...${NC}"
cargo publish --dry-run

# Confirm after dry run
echo ""
read -p "Dry-run successful. Proceed with actual publish? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Publication cancelled."
    exit 0
fi

# Publish
echo ""
echo -e "${YELLOW}Publishing to crates.io...${NC}"
cargo publish

echo ""
echo -e "${GREEN}✓ Successfully published veil-crypto@${VERSION}!${NC}"
echo ""
echo "📦 View on crates.io: https://crates.io/crates/veil-crypto"
echo ""
echo "📥 Use in Cargo.toml:"
echo "    veil-crypto = \"${VERSION}\""
echo ""
echo -e "${GREEN}🎉 Done!${NC}"
