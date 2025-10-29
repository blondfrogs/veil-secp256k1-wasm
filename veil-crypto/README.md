# veil-crypto

Pure Rust implementation of secp256k1 cryptographic primitives for Veil blockchain.

[![Crates.io](https://img.shields.io/crates/v/veil-crypto.svg)](https://crates.io/crates/veil-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)

## Overview

`veil-crypto` is a pure Rust cryptography library that implements all the cryptographic primitives needed for Veil's privacy features. Unlike traditional implementations that rely on C libraries (libsecp256k1-zkp), this library is 100% Rust, making it fully compatible with WebAssembly and safe from memory-related vulnerabilities.

## Features

- **Pure Rust** - No C dependencies, fully WASM-compatible
- **Pedersen Commitments** - Hide transaction amounts
- **Range Proofs** - Prove values are valid without revealing them
- **MLSAG Ring Signatures** - Anonymous sender via ring signatures
- **Borromean Ring Signatures** - Efficient ring signatures
- **Key Images** - Prevent double-spending with hash-to-curve
- **ECDH** - Shared secret generation for stealth addresses
- **Stealth Keys** - Derive one-time keys for recipients

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
veil-crypto = "0.1"
```

## Usage Examples

### Pedersen Commitments

```rust
use veil_crypto::pedersen_commit;

let value = 1000u64;
let blind = [0xAA; 32];  // Blinding factor

let commitment = pedersen_commit(value, &blind)?;
println!("Commitment: {}", hex::encode(&commitment));
```

### Range Proofs

```rust
use veil_crypto::{pedersen_commit, rangeproof_sign, rangeproof_verify};

let value = 1000u64;
let blind = [0xAA; 32];
let commitment = pedersen_commit(value, &blind)?;

// Generate range proof
let proof = rangeproof_sign(
    &commitment,
    value,
    &blind,
    &commitment,
    &[],  // extra_commit
    0,    // min_value
    -1,   // exp (auto)
    0,    // min_bits
)?;

// Verify range proof
let valid = rangeproof_verify(&commitment, &proof.proof)?;
assert!(valid);
```

### MLSAG Ring Signatures

```rust
use veil_crypto::{prepare_mlsag, generate_mlsag, verify_mlsag};

// Prepare MLSAG context
let context = prepare_mlsag(
    &message,
    ring_size,
    real_index,
    &private_keys,
    &public_keys,
    &commitments,
)?;

// Generate signature
let signature = generate_mlsag(&context)?;

// Verify signature
let valid = verify_mlsag(
    &message,
    &signature,
    &public_keys,
    &commitments,
)?;
assert!(valid);
```

### Key Image Generation

```rust
use veil_crypto::generate_keyimage;

let secret_key = [0xAB; 32];
let key_image = generate_keyimage(&secret_key)?;
```

### ECDH Shared Secrets

```rust
use veil_crypto::ecdh_veil;

let secret_key = [0xCD; 32];
let public_key = [0x02; 33];  // Compressed pubkey

let shared_secret = ecdh_veil(&secret_key, &public_key)?;
```

## Architecture

### Core Modules

- **`utils.rs`** - EC operations (derive_pubkey, point_add_scalar, etc.)
- **`ecdh.rs`** - ECDH_VEIL implementation for stealth addresses
- **`keyimage.rs`** - Key image generation using hash-to-curve
- **`pedersen.rs`** - Pedersen commitments with QR format handling
- **`rangeproof.rs`** - Bulletproof-style range proofs
- **`mlsag.rs`** - MLSAG signatures (870 lines, fully tested)
- **`borromean.rs`** - Borromean ring signatures

### Dependencies

All dependencies are pure Rust and WASM-compatible:

- **k256** - secp256k1 elliptic curve arithmetic
- **sha2** - SHA-256 hashing
- **sha3** - Keccak hashing
- **hmac** - HMAC-DRBG for deterministic randomness

## Testing

```bash
cd veil-crypto
cargo test

# Output:
# running 62 tests
# test result: ok. 62 passed; 0 failed
```

### Test Coverage

- ✅ ECDH (1 test)
- ✅ Pedersen commitments (7 tests)
- ✅ Key images (3 tests)
- ✅ Range proofs (12 tests)
- ✅ Borromean signatures (9 tests)
- ✅ MLSAG (1 comprehensive test)
- ✅ Utilities (29 tests)

All tests use vectors generated from the original C implementation to ensure compatibility.

## Critical Discovery: Pedersen QR Format

During development, we discovered a critical bug in how Pedersen format (0x08/0x09) commitments are converted to standard format (0x02/0x03).

**The Problem:** Simple bit mapping fails for ~50% of points because Pedersen format encodes based on **quadratic residue (QR)**, not y-coordinate parity.

**The Solution:** Compute canonical y-coordinate via `sqrt(x³ + 7)`, check parity, then select the correct point based on the format prefix bit.

See `veil-crypto/src/pedersen.rs` for implementation details. This fix is critical for MLSAG signature validity.

## WASM Support

This library is designed to compile to WebAssembly. For JavaScript/TypeScript bindings, see the companion package:

- [`@veil/secp256k1-wasm`](../veil-wasm) - WASM bindings for browser and Node.js

## Security Considerations

**Status:** Ready for integration testing

This implementation is:
- ✅ Feature complete
- ✅ Fully tested (62 tests passing)
- ✅ Byte-perfect compatible with Veil Core
- ✅ Pure Rust (memory-safe)

**For production use:**
- ⚠️ Professional security audit recommended
- ⚠️ Constant-time operations should be verified
- ⚠️ Side-channel analysis suggested
- ⚠️ Use on testnet first

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Pedersen commitment | ~0.5ms | Pure Rust k256 |
| Range proof generation | ~50-100ms | CPU-intensive |
| MLSAG generation | ~50-100ms | Per input |
| Key image generation | ~1-2ms | Hash-to-curve |

## Documentation

Generate and view the full API documentation:

```bash
cargo doc --open
```

## Contributing

Contributions welcome! Please ensure:

1. All tests pass: `cargo test`
2. Code is formatted: `cargo fmt`
3. No warnings: `cargo clippy`
4. Add tests for new features

## License

MIT License - See [LICENSE](../LICENSE) for details

## Related Projects

- **[veil-wasm](../veil-wasm)** - WASM bindings for JavaScript/TypeScript
- **[Veil Core](https://github.com/Veil-Project/veil)** - Official Veil blockchain
- **[Monero](https://github.com/monero-project/monero)** - Original RingCT research

## Support

- **Issues:** [GitHub Issues](https://github.com/blondfrogs/veil-secp256k1-wasm/issues)
- **Discussions:** [GitHub Discussions](https://github.com/blondfrogs/veil-secp256k1-wasm/discussions)

---

Built with 🦀 Rust for the Veil community
