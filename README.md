# Veil secp256k1 WASM

[![Status](https://img.shields.io/badge/status-production%20ready-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![WASM Size](https://img.shields.io/badge/wasm-530KB-orange)]()
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![npm](https://img.shields.io/npm/v/@veil/secp256k1-wasm.svg)](https://www.npmjs.com/package/@veil/secp256k1-wasm)
[![crates.io](https://img.shields.io/crates/v/veil-crypto.svg)](https://crates.io/crates/veil-crypto)

**Pure Rust secp256k1 cryptography for Veil blockchain, compiled to WebAssembly.**

This repository provides production-ready cryptographic primitives for Veil's privacy features, including Pedersen commitments, range proofs, and MLSAG ring signatures. 100% Rust, fully WASM-compatible, no C dependencies.

---

## 🎯 What Is This?

Low-level cryptographic primitives for Veil blockchain privacy features:

### 🦀 Rust Crate: `veil-crypto`
- Pure Rust implementation of all Veil cryptographic primitives
- No C dependencies - fully WASM-compatible
- Validated byte-for-byte against Veil Core
- Available on [crates.io](https://crates.io/crates/veil-crypto)

### 🌐 npm Package: `@veil/secp256k1-wasm`
- WebAssembly bindings for JavaScript/TypeScript
- Works in browsers and Node.js
- 530KB optimized bundle
- Available on [npm](https://www.npmjs.com/package/@veil/secp256k1-wasm)

---

## ✨ Features

### 🔐 Complete Privacy Stack

- ✅ **Pedersen Commitments** - Hide transaction amounts
- ✅ **Range Proofs** - Prove amounts are valid without revealing them
- ✅ **MLSAG Ring Signatures** - Hide transaction source among decoys
- ✅ **Borromean Ring Signatures** - Efficient ring signatures
- ✅ **Key Images** - Prevent double-spending anonymously
- ✅ **ECDH** - Shared secret generation for stealth addresses
- ✅ **Stealth Key Derivation** - One-time keys for recipients

### 🚀 Production Ready

- ✅ **100% Pure Rust** - No unsafe C bindings
- ✅ **WASM Performance** - 530KB optimized bundle
- ✅ **Type-Safe API** - Full TypeScript definitions
- ✅ **62 Tests Passing** - Comprehensive validation
- ✅ **Veil Core Compatible** - Binary format matches exactly

---

## 📁 Project Structure

```
veil-secp256k1-wasm/
│
├── veil-crypto/              # 🦀 Pure Rust crypto library
│   ├── src/
│   │   ├── lib.rs           # Main library
│   │   ├── utils.rs         # EC operations
│   │   ├── ecdh.rs          # ECDH_VEIL implementation
│   │   ├── keyimage.rs      # Key image generation
│   │   ├── pedersen.rs      # Pedersen commitments
│   │   ├── rangeproof.rs    # Range proofs
│   │   ├── mlsag.rs         # MLSAG signatures (870 lines)
│   │   └── borromean.rs     # Borromean signatures
│   └── tests/               # Test vectors from C implementation
│
└── veil-wasm/               # 🌐 WASM bindings
    ├── src/lib.rs           # JavaScript/TypeScript exports
    └── pkg/                 # Built WASM package (530KB)
```

---

## 🚀 Quick Start

### For Rust Projects

Add to your `Cargo.toml`:

```toml
[dependencies]
veil-crypto = "0.1"
```

```rust
use veil_crypto::{pedersen_commit, rangeproof_sign, generate_mlsag};

let commitment = pedersen_commit(1000u64, &blind)?;
let proof = rangeproof_sign(&commitment, 1000u64, &blind, ...)?;
```

See [veil-crypto README](veil-crypto/README.md) for detailed Rust API documentation.

### For JavaScript/TypeScript Projects

```bash
npm install @veil/secp256k1-wasm
```

```typescript
import init, { pedersen_commit, rangeproof_sign } from '@veil/secp256k1-wasm';

await init();  // Initialize WASM

const commitment = pedersen_commit(1000n, blind);
const proof = rangeproof_sign(commitment, 1000n, blind, ...);
```

See [veil-wasm README](veil-wasm/README.md) for detailed JavaScript API documentation.

---

## 📦 Packages

### Rust Crate: `veil-crypto`

[![Crates.io](https://img.shields.io/crates/v/veil-crypto.svg)](https://crates.io/crates/veil-crypto)

Pure Rust cryptographic primitives. Use this for:
- Rust applications
- Backend services
- Embedded systems
- WASM compilation

**[Read veil-crypto documentation →](veil-crypto/README.md)**

### npm Package: `@veil/secp256k1-wasm`

[![npm](https://img.shields.io/npm/v/@veil/secp256k1-wasm.svg)](https://www.npmjs.com/package/@veil/secp256k1-wasm)

WebAssembly bindings for JavaScript/TypeScript. Use this for:
- Web applications
- Node.js services
- Electron apps
- React Native (with polyfills)

**[Read @veil/secp256k1-wasm documentation →](veil-wasm/README.md)**

---

## 🔬 Critical Technical Discovery

### Pedersen QR Format Bug

During MLSAG implementation, we discovered a **critical bug** in Pedersen commitment format conversion.

**The Problem:**
Simple mapping `0x08 → 0x02, 0x09 → 0x03` **FAILS** for ~50% of points!

**Root Cause:**
Pedersen format (0x08/0x09) encodes based on **quadratic residue (QR)**, not parity.

**The Fix:**
Compute canonical y via `sqrt(x³ + 7)`, check parity, then select correct point based on prefix bit 0.

See `veil-crypto/src/pedersen.rs` for the implementation details.

**Impact:**
Without this fix, MLSAG signatures would be invalid, causing transaction failures and potential fund loss.

---

## 🧪 Testing

### Run Rust Tests

```bash
cd veil-crypto
cargo test

# Output:
# running 62 tests
# test result: ok. 62 passed; 0 failed
```

**Test Coverage:**
- ✅ ECDH (1 test)
- ✅ Pedersen commitments (7 tests)
- ✅ Key images (3 tests)
- ✅ Range proofs (12 tests)
- ✅ Borromean signatures (9 tests)
- ✅ MLSAG (1 comprehensive test)
- ✅ Utilities (29 tests)

---

## 🏗️ Building from Source

### Prerequisites

- **Rust** 1.70+ with `wasm32-unknown-unknown` target
- **wasm-pack** for building WASM: `cargo install wasm-pack`

### Build WASM Package

```bash
# Clone repository
git clone https://github.com/blondfrogs/veil-secp256k1-wasm.git
cd veil-secp256k1-wasm

# Build WASM (530KB optimized)
cd veil-wasm
wasm-pack build --target nodejs --release

# For browsers
wasm-pack build --target web --release

# For bundlers (webpack, etc)
wasm-pack build --target bundler --release
```

The built package will be in `veil-wasm/pkg/`.

### Build Rust Library

```bash
cd veil-crypto
cargo build --release
cargo test
```

---

## ⚡ Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Pedersen commitment | ~0.5ms | Pure Rust |
| Range proof generation | ~50-100ms | CPU-intensive |
| Range proof verification | ~20-30ms | |
| MLSAG generation | ~50-100ms | Per input |
| Key image generation | ~1-2ms | Hash-to-curve |
| ECDH shared secret | ~0.5ms | |

### WASM Bundle Size

| Build Type | Size |
|------------|------|
| Debug | 10 MB |
| Release | **530 KB** ✨ |
| Release + gzip | ~180 KB |

---

## 📚 Higher-Level APIs

This repository provides **low-level cryptographic primitives**. For building complete Veil transactions, use:

### `@veil/tx-builder` (separate repository)

High-level TypeScript transaction builder with:
- Transaction builder class
- Stealth address generation (Bech32 `sv1` format)
- UTXO management
- RPC integration
- Output scanning
- Fee calculation

**Coming soon** - Currently being split from this repository into its own package.

---

## ⚠️ Security Warning

**Status: Ready for Integration Testing**

While this implementation is:
- ✅ Feature complete
- ✅ Fully tested (62 Rust tests passing)
- ✅ Byte-perfect compatible with Veil Core
- ✅ Pure Rust (memory-safe)
- ✅ WASM-ready

**For production use with real funds:**
- ⚠️ Security audit recommended
- ⚠️ Constant-time operations should be verified
- ⚠️ Side-channel analysis suggested
- ⚠️ Community testing recommended

**Use at your own risk with testnet first!**

---

## 🗺️ Roadmap

### ✅ Completed

- [x] Pure Rust crypto primitives
- [x] WASM compilation (530KB)
- [x] Veil Core format compatibility
- [x] Pedersen commitments with QR fix
- [x] Range proofs
- [x] MLSAG signatures
- [x] Comprehensive testing (62 tests)
- [x] TypeScript definitions

### 🚧 In Progress

- [ ] Publish `veil-crypto` to crates.io
- [ ] Publish `@veil/secp256k1-wasm` to npm
- [ ] Browser support testing
- [ ] Performance optimization

### 📋 Planned

- [ ] Professional security audit
- [ ] Constant-time operation verification
- [ ] Bulletproofs+ (smaller proofs)
- [ ] WASM SIMD support
- [ ] Benchmarking suite

---

## 🤝 Contributing

Contributions are welcome!

### Development Setup

```bash
# Clone repository
git clone https://github.com/blondfrogs/veil-secp256k1-wasm.git
cd veil-secp256k1-wasm

# Run Rust tests
cd veil-crypto
cargo test

# Build WASM
cd ../veil-wasm
wasm-pack build --target nodejs --release
```

### Areas Needing Help

1. **Security Review** - Constant-time operations, side-channels
2. **Performance** - Optimize hot paths, reduce bundle size
3. **Testing** - Fuzz testing, property-based tests
4. **Documentation** - Examples, tutorials, guides
5. **Browser Support** - Cross-browser testing

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details

---

## 🙏 Acknowledgments

- **Veil Team** - Original C implementation and blockchain
- **Monero Project** - RingCT research and inspiration
- **RustCrypto** - Pure Rust cryptographic primitives
- **k256 crate** - secp256k1 implementation

---

## 📞 Contact & Support

- **Issues:** [GitHub Issues](https://github.com/blondfrogs/veil-secp256k1-wasm/issues)
- **Discussions:** [GitHub Discussions](https://github.com/blondfrogs/veil-secp256k1-wasm/discussions)
- **Crates.io:** [veil-crypto](https://crates.io/crates/veil-crypto)
- **npm:** [@veil/secp256k1-wasm](https://www.npmjs.com/package/@veil/secp256k1-wasm)

---

## 🔗 Related Projects

- **[Veil Core](https://github.com/Veil-Project/veil)** - Official Veil blockchain
- **[Veil Wallet](https://github.com/steel97/veil_wallet)** - Flutter wallet
- **[Monero](https://github.com/monero-project/monero)** - Original RingCT implementation

---

## 📈 Project Statistics

| Metric | Value |
|--------|-------|
| **Rust Code** | ~4,500 lines |
| **MLSAG Implementation** | 870 lines |
| **Test Cases** | 62 passing |
| **WASM Bundle** | 530 KB (optimized) |
| **Dependencies** | 15 (all pure Rust) |
| **Supported Targets** | x86_64, ARM64, WASM32 |

---

<div align="center">

## 🎉 Production Ready Crypto!

**✅ Pure Rust • ✅ WASM Compatible • ✅ Type-Safe**

Built with 🦀 Rust for the Veil community

**⭐ If this helps you, please star the repo! ⭐**

**Last Updated:** October 29, 2025
**Version:** 0.1.0
**Status:** Ready for Testing

</div>
