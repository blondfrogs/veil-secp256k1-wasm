#!/bin/bash
# Build script for Veil WASM

set -e  # Exit on error

echo "🔧 Building Veil WASM..."

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "❌ wasm-pack not found!"
    echo "Install it with: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
    exit 1
fi

# Clean previous build
echo -e "${YELLOW}Cleaning previous build...${NC}"
rm -rf veil-wasm/pkg

# Build veil-crypto first
echo -e "${YELLOW}Building veil-crypto library...${NC}"
cd veil-crypto
cargo build --release
cd ..

# Build WASM module
echo -e "${YELLOW}Building WASM module...${NC}"
cd veil-wasm
wasm-pack build --target web --release

# Extract metadata from workspace Cargo.toml
VERSION=$(grep -m1 '^version' ../Cargo.toml | cut -d'"' -f2)
DESCRIPTION=$(grep -m1 '^description' ../Cargo.toml | cut -d'"' -f2)
LICENSE=$(grep -m1 '^license' ../Cargo.toml | cut -d'"' -f2)

# Extract authors array and convert to JSON format
AUTHORS=$(grep -m1 '^authors' ../Cargo.toml | sed 's/authors = //' | sed 's/\[/[/;s/\]/]/')
AUTHOR=$(echo "$AUTHORS" | sed 's/\["\([^"]*\)".*/\1/')  # First author as main author
CONTRIBUTORS=$(echo "$AUTHORS")  # All authors as contributors

# Get git metadata
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo -e "${YELLOW}Using version: ${VERSION}${NC}"
echo -e "${YELLOW}Using authors: ${AUTHORS}${NC}"
echo -e "${YELLOW}Git commit: ${GIT_COMMIT} (${GIT_BRANCH})${NC}"
echo -e "${YELLOW}Build date: ${BUILD_DATE}${NC}"

# Update package.json with our custom metadata from template
echo -e "${YELLOW}Updating package.json metadata...${NC}"
sed \
  -e "s/{{VERSION}}/${VERSION}/g" \
  -e "s/{{DESCRIPTION}}/${DESCRIPTION}/g" \
  -e "s/{{LICENSE}}/${LICENSE}/g" \
  -e "s/{{AUTHOR}}/${AUTHOR}/g" \
  -e "s/{{CONTRIBUTORS}}/${CONTRIBUTORS}/g" \
  -e "s/{{GIT_COMMIT}}/${GIT_COMMIT}/g" \
  -e "s/{{GIT_BRANCH}}/${GIT_BRANCH}/g" \
  -e "s/{{BUILD_DATE}}/${BUILD_DATE}/g" \
  package.json.template > pkg/package.json

# Copy README
cp README.md pkg/

# Check the size
echo -e "${GREEN}✓ Build complete!${NC}"
echo ""
echo "Output:"
ls -lh pkg/*.wasm
echo ""
echo "Bundle size:"
du -h pkg/*.wasm

cd ..
