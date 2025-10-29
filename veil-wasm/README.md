# @veil/secp256k1-wasm

WebAssembly bindings for Veil's pure Rust secp256k1 cryptography library.

[![npm version](https://img.shields.io/npm/v/@veil/secp256k1-wasm.svg)](https://www.npmjs.com/package/@veil/secp256k1-wasm)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![WASM Size](https://img.shields.io/badge/wasm-530KB-orange.svg)]()

## Overview

`@veil/secp256k1-wasm` provides JavaScript/TypeScript bindings for the `veil-crypto` Rust library, compiled to WebAssembly. This enables privacy-preserving cryptographic operations in web browsers and Node.js environments.

## Features

- **Pure Rust compiled to WASM** - No native dependencies
- **530KB optimized bundle** - Small footprint
- **Full TypeScript support** - Complete type definitions
- **Browser + Node.js** - Works everywhere
- **Pedersen Commitments** - Hide transaction amounts
- **Range Proofs** - Prove values without revealing them
- **MLSAG Ring Signatures** - Anonymous transactions
- **Key Images** - Prevent double-spending
- **ECDH** - Shared secret generation

## Installation

```bash
npm install @veil/secp256k1-wasm
```

Or with yarn:

```bash
yarn add @veil/secp256k1-wasm
```

## Usage

### Initialize WASM

```typescript
import init, {
  pedersen_commit,
  rangeproof_sign,
  rangeproof_verify,
  generate_mlsag,
  derive_pubkey,
  ecdh_veil
} from '@veil/secp256k1-wasm';

// Initialize WASM module (call once at startup)
await init();
```

### Pedersen Commitments

```typescript
import { pedersen_commit } from '@veil/secp256k1-wasm';

const value = 1000n;  // Amount to commit
const blind = new Uint8Array(32);  // Blinding factor (use crypto.getRandomValues)
crypto.getRandomValues(blind);

const commitment = pedersen_commit(value, blind);
console.log('Commitment:', commitment);  // 33 bytes
```

### Range Proofs

```typescript
import { pedersen_commit, rangeproof_sign, rangeproof_verify } from '@veil/secp256k1-wasm';

const value = 1000n;
const blind = new Uint8Array(32);
crypto.getRandomValues(blind);

const commitment = pedersen_commit(value, blind);

// Generate proof that value is in valid range
const proofResult = rangeproof_sign(
  commitment,
  value,
  blind,
  commitment,  // nonce_commit
  new Uint8Array(0),  // extra_commit
  0n,  // min_value
  -1,  // exp (auto)
  0   // min_bits
);

console.log('Proof size:', proofResult.proof.length);
console.log('Message:', proofResult.message);

// Verify proof
const isValid = rangeproof_verify(commitment, proofResult.proof);
console.log('Valid:', isValid);  // true
```

### MLSAG Ring Signatures

```typescript
import { prepare_mlsag, generate_mlsag, verify_mlsag } from '@veil/secp256k1-wasm';

const message = new Uint8Array(32);  // Message to sign
const ringSize = 11;
const realIndex = 5;  // Your real output position

// Prepare MLSAG context
const context = prepare_mlsag(
  message,
  ringSize,
  realIndex,
  privateKeys,    // Array of your secret keys
  publicKeys,     // Ring of public keys
  commitments     // Ring of commitments
);

// Generate signature
const signature = generate_mlsag(context);

// Verify signature
const isValid = verify_mlsag(message, signature, publicKeys, commitments);
console.log('Valid MLSAG:', isValid);
```

### Key Derivation

```typescript
import { derive_pubkey, ecdh_veil } from '@veil/secp256k1-wasm';

// Derive public key from private key
const secretKey = new Uint8Array(32);
crypto.getRandomValues(secretKey);

const publicKey = derive_pubkey(secretKey);
console.log('Public key:', publicKey);  // 33 bytes compressed

// ECDH shared secret
const recipientPubkey = new Uint8Array(33);  // Their public key
const sharedSecret = ecdh_veil(secretKey, recipientPubkey);
console.log('Shared secret:', sharedSecret);  // 32 bytes
```

### Key Images

```typescript
import { generate_keyimage } from '@veil/secp256k1-wasm';

const secretKey = new Uint8Array(32);
crypto.getRandomValues(secretKey);

const keyImage = generate_keyimage(secretKey);
console.log('Key image:', keyImage);  // 33 bytes
```

## API Reference

### Commitment Functions

- `pedersen_commit(value: bigint, blind: Uint8Array): Uint8Array` - Create Pedersen commitment
- `pedersen_commit_with_generator(value: bigint, blind: Uint8Array, generator: Uint8Array): Uint8Array` - Commit with custom generator

### Range Proof Functions

- `rangeproof_sign(...): RangeProofResult` - Generate range proof
- `rangeproof_verify(commitment: Uint8Array, proof: Uint8Array): boolean` - Verify range proof
- `rangeproof_rewind(commitment: Uint8Array, proof: Uint8Array, nonce: Uint8Array): RewindResult | null` - Rewind proof to extract value

### MLSAG Functions

- `prepare_mlsag(...): MlsagContext` - Prepare MLSAG signing context
- `generate_mlsag(context: MlsagContext): Uint8Array` - Generate MLSAG signature
- `verify_mlsag(...): boolean` - Verify MLSAG signature

### Key Functions

- `derive_pubkey(secretKey: Uint8Array): Uint8Array` - Derive public key
- `point_add_scalar(pubkey: Uint8Array, scalar: Uint8Array): Uint8Array` - Add scalar to point
- `generate_keyimage(secretKey: Uint8Array): Uint8Array` - Generate key image

### ECDH Functions

- `ecdh_veil(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array` - Compute shared secret

## TypeScript Types

The package includes full TypeScript definitions:

```typescript
export interface RangeProofResult {
  proof: Uint8Array;
  message: Uint8Array;
}

export interface RewindResult {
  value: bigint;
  blind: Uint8Array;
  message: Uint8Array;
}

export interface MlsagContext {
  // Internal context for MLSAG signing
}
```

## Bundle Size

| Build Type | Size |
|------------|------|
| WASM (release) | 530 KB |
| WASM (gzipped) | ~180 KB |
| JS wrapper | ~5 KB |

## Browser Support

Works in all modern browsers that support WebAssembly:

- Chrome/Edge 57+
- Firefox 52+
- Safari 11+
- Node.js 12+

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Pedersen commitment | ~0.5ms | |
| Range proof generation | ~50-100ms | CPU-intensive |
| MLSAG generation | ~50-100ms | Per input |
| Range proof verification | ~20-30ms | |
| Key derivation | ~0.5ms | |

## Security Considerations

**Status:** Ready for integration testing

This implementation is:
- ✅ Pure Rust (memory-safe)
- ✅ WASM-isolated sandbox
- ✅ No eval() or dynamic code
- ✅ Fully tested

**For production use:**
- ⚠️ Professional security audit recommended
- ⚠️ Test on testnet first
- ⚠️ Use secure random number generation
- ⚠️ Protect private keys

## Building from Source

Requires Rust 1.70+ and wasm-pack:

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for Node.js
wasm-pack build --target nodejs --release

# Build for browsers
wasm-pack build --target web --release

# Build for bundlers (webpack, etc)
wasm-pack build --target bundler --release
```

The built package will be in `pkg/`.

## Examples

See the `examples/` directory for complete examples:

- Basic commitment and range proof
- MLSAG ring signature generation
- Key derivation and ECDH
- Integration with transaction building

## Rust Crate

For Rust projects, use the underlying crate directly:

```toml
[dependencies]
veil-crypto = "0.1"
```

See [`veil-crypto` documentation](../veil-crypto) for Rust API.

## Higher-Level APIs

For transaction building, use the companion package:

- **`@veil/tx-builder`** (separate repo) - High-level transaction builder

## Contributing

Contributions welcome! Please:

1. Test your changes: `npm test`
2. Ensure WASM builds: `wasm-pack build`
3. Update documentation
4. Add tests for new features

## License

MIT License - See [LICENSE](../LICENSE) for details

## Related Projects

- **[veil-crypto](../veil-crypto)** - Pure Rust cryptography library
- **[Veil Core](https://github.com/Veil-Project/veil)** - Official Veil blockchain
- **[wasm-bindgen](https://github.com/rustwasm/wasm-bindgen)** - Rust-WASM bindings

## Support

- **Issues:** [GitHub Issues](https://github.com/blondfrogs/veil-secp256k1-wasm/issues)
- **Discussions:** [GitHub Discussions](https://github.com/blondfrogs/veil-secp256k1-wasm/discussions)
- **npm:** [@veil/secp256k1-wasm](https://www.npmjs.com/package/@veil/secp256k1-wasm)

---

Built with 🦀 Rust + 🕸️ WASM for the Veil community
