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

# Check the size
echo -e "${GREEN}✓ Build complete!${NC}"
echo ""
echo "Output:"
ls -lh pkg/*.wasm
echo ""
echo "Bundle size:"
du -h pkg/*.wasm

cd ..
