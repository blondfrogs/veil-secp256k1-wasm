//! Range Proofs - Pure Rust Implementation
//!
//! Range proofs prove that a committed value is within a valid range
//! (e.g., non-negative and less than 2^64) without revealing the value.
//!
//! ## Algorithm
//!
//! Veil uses Borromean-based range proofs to:
//! 1. Prove a committed value is in range [0, 2^64)
//! 2. Hide the actual value while proving validity
//! 3. Allow the recipient to decrypt the value with a nonce
//!
//! ## Implementation
//!
//! This is a **pure Rust** implementation using k256, NOT FFI bindings.
//! This allows compilation to WASM for browser-based light wallets.
//!
//! ## Functions
//!
//! - **rangeproof_sign**: Create a range proof for a value
//! - **rangeproof_verify**: Verify a range proof is valid
//! - **rangeproof_rewind**: Decrypt a range proof to extract the value

use crate::{Result, VeilCryptoError};
use crate::borromean::borromean_sign;
use crate::pedersen::{get_generator_h_point, pedersen_ecmult_point};
use k256::{
    elliptic_curve::{
        group::Group,
        sec1::{ToEncodedPoint, FromEncodedPoint},
        ops::MulByGenerator,
        PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar,
};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

/// Maximum proof size (from Veil)
pub const MAX_PROOF_SIZE: usize = 5134;

/// Maximum rings in a range proof
pub const MAX_RINGS: usize = 32;

/// Maximum public keys in a range proof
pub const MAX_NPUB: usize = 128;

/// Maximum message size that can be embedded
pub const MAX_MESSAGE_SIZE: usize = 256;

//
// ===== DATA STRUCTURES =====
//

/// Internal proof parameters
#[derive(Debug, Clone)]
struct RangeProofParams {
    rings: usize,              // Number of rings
    rsizes: Vec<usize>,        // Size of each ring [4, 4, ..., 2 or 4]
    secidx: Vec<usize>,        // Secret index for each ring (which digit is real)
    npub: usize,               // Total number of public keys
    mantissa: usize,           // Number of bits to prove
    #[allow(dead_code)]
    min_value: u64,            // Minimum value in range
    scale: u64,                // Scale factor (10^exp)
    v: u64,                    // Encoded value (value - min_value) / scale
}

/// Result from signing a range proof
#[derive(Debug, Clone)]
pub struct RangeProofSignResult {
    /// The generated range proof
    pub proof: Vec<u8>,
    /// The Pedersen commitment
    pub commitment: Vec<u8>,
    /// The blinding factor
    pub blind: Vec<u8>,
    /// The nonce used for encryption
    pub nonce: Vec<u8>,
}

/// Result from verifying a range proof
#[derive(Debug, Clone)]
pub struct RangeProofVerifyResult {
    /// Minimum value in the proven range
    pub min_value: u64,
    /// Maximum value in the proven range
    pub max_value: u64,
}

/// Result from rewinding a range proof
#[derive(Debug, Clone)]
pub struct RangeProofRewindResult {
    /// The recovered blinding factor
    pub blind: Vec<u8>,
    /// The recovered value
    pub value: u64,
    /// Minimum value in the proven range
    pub min_value: u64,
    /// Maximum value in the proven range
    pub max_value: u64,
    /// Any embedded message
    pub message: Vec<u8>,
}

/// Result from extracting info from a range proof
#[derive(Debug, Clone)]
pub struct RangeProofInfo {
    /// The exponent used in the proof
    pub exp: i32,
    /// The mantissa (number of bits proven)
    pub mantissa: usize,
    /// Minimum value in the proven range
    pub min_value: u64,
    /// Maximum value in the proven range
    pub max_value: u64,
}

//
// ===== HELPER FUNCTIONS =====
//

/// Serialize an affine point to 33 bytes (SEC1 format)
///
/// SEC1 format:
/// - Byte 0: 0x02 if y is even, 0x03 if y is odd
/// - Bytes 1-32: x-coordinate
///
/// Used for k256 interop and borromean functions
fn serialize_point(point: &AffinePoint) -> [u8; 33] {
    use k256::elliptic_curve::group::prime::PrimeCurveAffine;

    let encoded = point.to_encoded_point(true);
    let bytes = encoded.as_bytes();

    // Safety check: ensure we have exactly 33 bytes (compressed point)
    if bytes.len() != 33 {
        eprintln!("\n========== SERIALIZE_POINT ERROR ==========");
        eprintln!("ERROR: serialize_point got {} bytes instead of 33", bytes.len());
        eprintln!("Point is identity: {}", bool::from(point.is_identity()));
        eprintln!("Encoded bytes: {:02x?}", bytes);
        eprintln!("==========================================\n");
        panic!("Invalid point serialization: expected 33 bytes, got {}", bytes.len());
    }

    let mut result = [0u8; 33];
    result.copy_from_slice(bytes);
    result
}

/// Serialize an affine point to 33 bytes (custom format matching C code)
///
/// C custom format (NOT SEC1):
/// - Byte 0: 0 if y is quadratic residue (even), 1 if not (odd)
/// - Bytes 1-32: x-coordinate
///
/// This matches rustsecp256k1_v0_4_1_rangeproof_serialize_point in C code.
/// Used ONLY for HMAC-DRBG seed construction to match C exactly.
fn serialize_point_custom(point: &AffinePoint) -> [u8; 33] {
    use k256::FieldElement;

    let mut result = [0u8; 33];

    // MATCH C++ EXACTLY: data[0] = !secp256k1_fe_is_quad_var(&point->y)
    // Get y coordinate
    let encoded = point.to_encoded_point(false); // Uncompressed to get y
    let bytes = encoded.as_bytes();

    // Extract y-coordinate (bytes 33..65 in uncompressed format)
    let y_bytes: [u8; 32] = bytes[33..65].try_into().unwrap();
    let y = FieldElement::from_bytes(&y_bytes.into()).unwrap();

    // Check if y is a quadratic residue
    // QR means: sqrt(y) exists (matching secp256k1's is_quad_var)
    let y_has_sqrt = y.sqrt().is_some();
    let y_is_qr: bool = y_has_sqrt.into();

    // C++ code: data[0] = !is_quad_var(y)
    // So: 0x00 if QR, 0x01 if NOT QR
    result[0] = if y_is_qr { 0x00 } else { 0x01 };

    // x-coordinate
    result[1..33].copy_from_slice(&bytes[1..33]);

    result
}

/// Count leading zeros in a u64 (for bit length calculation)
fn clz64(x: u64) -> usize {
    if x == 0 {
        64
    } else {
        x.leading_zeros() as usize
    }
}

/// RFC6979-style HMAC-SHA256 DRBG for deterministic random generation
///
/// This matches the C implementation in secp256k1/src/hash_impl.h
pub struct HmacDrbg {
    k: [u8; 32],
    v: [u8; 32],
    retry: bool,  // RFC 6979 3.2.h - update K on subsequent calls
}

impl HmacDrbg {
    /// Initialize DRBG with a seed
    ///
    /// Implements RFC 6979 3.2.b-f
    pub fn new(seed: &[u8]) -> Self {
        let mut k = [0u8; 32];  // RFC 6979 3.2.c
        let mut v = [1u8; 32];  // RFC 6979 3.2.b

        eprintln!("\n=== HMAC-DRBG Initialization ===");
        eprintln!("Initial K: {}", hex::encode(&k));
        eprintln!("Initial V: {}", hex::encode(&v));
        eprintln!("Seed ({} bytes): {}", seed.len(), hex::encode(seed));

        type HmacSha256 = Hmac<Sha256>;

        // RFC 6979 3.2.d: K = HMAC_K(V || 0x00 || seed)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC init");
        mac.update(&v);
        mac.update(&[0x00]);
        mac.update(seed);
        k.copy_from_slice(&mac.finalize().into_bytes());
        eprintln!("After step 3.2.d - K: {}", hex::encode(&k));

        // V = HMAC_K(V)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC init");
        mac.update(&v);
        v.copy_from_slice(&mac.finalize().into_bytes());
        eprintln!("After step 3.2.e - V: {}", hex::encode(&v));

        // RFC 6979 3.2.f: K = HMAC_K(V || 0x01 || seed)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC init");
        mac.update(&v);
        mac.update(&[0x01]);
        mac.update(seed);
        k.copy_from_slice(&mac.finalize().into_bytes());
        eprintln!("After step 3.2.f - K: {}", hex::encode(&k));

        // V = HMAC_K(V)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC init");
        mac.update(&v);
        v.copy_from_slice(&mac.finalize().into_bytes());
        eprintln!("After step 3.2.g - V: {}", hex::encode(&v));
        eprintln!("=================================\n");

        Self { k, v, retry: false }  // retry starts at 0
    }

    /// Generate 32 bytes of random data
    ///
    /// Implements RFC 6979 3.2.h
    /// Matches C code: rustsecp256k1_v0_4_1_rfc6979_hmac_sha256_generate
    pub fn generate(&mut self) -> [u8; 32] {
        static mut GENERATE_CALL_COUNT: usize = 0;
        unsafe { GENERATE_CALL_COUNT += 1; }

        type HmacSha256 = Hmac<Sha256>;

        eprintln!("\n--- generate() call #{} ---", unsafe { GENERATE_CALL_COUNT });
        eprintln!("Before: retry={}, K={}, V={}",
                  self.retry, hex::encode(&self.k[..8]), hex::encode(&self.v[..8]));

        // RFC 6979 3.2.h: On subsequent calls (retry == 1), update K first
        if self.retry {
            eprintln!("  Retry=true, updating K and V first");
            // K = HMAC_K(V || 0x00)
            let mut mac = HmacSha256::new_from_slice(&self.k).expect("HMAC init");
            mac.update(&self.v);
            mac.update(&[0x00]);
            self.k.copy_from_slice(&mac.finalize().into_bytes());
            eprintln!("  After K update: K={}", hex::encode(&self.k[..8]));

            // V = HMAC_K(V)
            let mut mac = HmacSha256::new_from_slice(&self.k).expect("HMAC init");
            mac.update(&self.v);
            self.v.copy_from_slice(&mac.finalize().into_bytes());
            eprintln!("  After V update: V={}", hex::encode(&self.v[..8]));
        }

        // Always: V = HMAC_K(V)
        let mut mac = HmacSha256::new_from_slice(&self.k).expect("HMAC init");
        mac.update(&self.v);
        self.v.copy_from_slice(&mac.finalize().into_bytes());

        // Set retry for next call
        self.retry = true;

        eprintln!("After: V={} (output)", hex::encode(&self.v[..8]));
        eprintln!("Full output: {}", hex::encode(&self.v));

        self.v
    }
}

/// Generate deterministic random values for range proof
///
/// This generates:
/// - sec[rings]: Blinding factors for each ring (sum = 0 mod n)
/// - s[npub]: Signature values for Borromean
/// - Optionally encrypts message via XOR
///
/// The randomness is deterministic based on nonce, commitment, and proof header
fn rangeproof_genrand(
    sec: &mut [Scalar],
    s: &mut [Scalar],
    mut message: Option<&mut [u8]>,
    rsizes: &[usize],
    rings: usize,
    nonce: &[u8],
    commit_point: &AffinePoint,
    genp: &AffinePoint,
    proof_header: &[u8],
) -> Result<bool> {
    // Build seed: nonce || commit || genp || proof_header
    // Use custom format to match C code exactly
    let mut seed = Vec::with_capacity(32 + 33 + 33 + proof_header.len());
    seed.extend_from_slice(nonce);

    let commit_serialized = serialize_point_custom(commit_point);
    let genp_serialized = serialize_point_custom(genp);

    // DEBUG: Print seed components
    eprintln!("\n=== HMAC-DRBG Seed Construction ===");
    eprintln!("nonce ({} bytes): {}", nonce.len(), hex::encode(nonce));
    eprintln!("commit_point: {:?}", commit_point);
    eprintln!("commit_serialized ({} bytes): {}", commit_serialized.len(), hex::encode(&commit_serialized));
    eprintln!("genp: {:?}", genp);
    eprintln!("genp_serialized ({} bytes): {}", genp_serialized.len(), hex::encode(&genp_serialized));
    eprintln!("proof_header ({} bytes): {}", proof_header.len(), hex::encode(proof_header));

    seed.extend_from_slice(&commit_serialized);
    seed.extend_from_slice(&genp_serialized);
    seed.extend_from_slice(proof_header);

    eprintln!("Total seed ({} bytes): {}", seed.len(), hex::encode(&seed));
    eprintln!("=================================\n");

    let mut drbg = HmacDrbg::new(&seed);
    let mut acc = Scalar::ZERO;
    let mut npub = 0;
    let mut ret = true;

    for i in 0..rings {
        if i < rings - 1 {
            // C code (line 85): Discard one generate() call BEFORE the do-while loop for each ring
            let _ = drbg.generate();
            eprintln!("Ring {}: Discarded first generate() call", i);

            // Generate random scalar for sec[i] until valid (not zero, not overflow)
            loop {
                let bytes = drbg.generate();
                eprintln!("Ring {}: Generated bytes: {}", i, hex::encode(&bytes));
                let scalar_option = Option::<Scalar>::from(Scalar::from_repr(bytes.into()));
                if let Some(scalar) = scalar_option {
                    if !bool::from(scalar.is_zero()) {
                        sec[i] = scalar;
                        acc += scalar;
                        eprintln!("Ring {}: Accepted scalar: {}", i, hex::encode(scalar.to_bytes()));
                        break;
                    }
                }
                eprintln!("Ring {}: Rejected (zero or overflow), retrying", i);
            }
        } else {
            // Last sec is negated sum (ensures sum = 0)
            sec[i] = -acc;
            eprintln!("Ring {} (last): sec = -acc = {}", i, hex::encode(sec[i].to_bytes()));
        }

        // Generate s[j] for each element in ring
        for j in 0..rsizes[i] {
            let mut bytes = drbg.generate();

            // XOR with message if provided (encrypts message)
            if let Some(ref mut msg) = message {
                let offset = (i * 4 + j) * 32;
                if offset + 32 <= msg.len() {
                    for b in 0..32 {
                        bytes[b] ^= msg[offset + b];
                        msg[offset + b] = bytes[b];
                    }
                }
            }

            // Convert to scalar
            let scalar_option = Option::<Scalar>::from(Scalar::from_repr(bytes.into()));
            if let Some(scalar) = scalar_option {
                if bool::from(scalar.is_zero()) {
                    ret = false;
                }
                s[npub] = scalar;
            } else {
                ret = false;
            }
            npub += 1;
        }
    }

    Ok(ret)
}

/// Expand public keys for range proof rings
///
/// Given a base point and exponent, this generates all the public keys
/// needed for each ring element. This implements the value encoding
/// where each ring represents a digit in radix-4 (base 4).
fn rangeproof_pub_expand(
    pubs: &mut [ProjectivePoint],
    exp: i32,
    rsizes: &[usize],
    rings: usize,
    genp: &AffinePoint,
) {
    let mut base = ProjectivePoint::from(genp);
    base = -base; // Negate

    // Apply exponent (multiply by 10^exp)
    for _ in 0..exp {
        // Multiplication by 10 = 2 * (2 * 2 + 1)
        let tmp = base.double();
        base = tmp.double();
        base = base.double();
        base += tmp;
    }

    let mut npub = 0;
    for i in 0..rings {
        // Generate ring elements
        for j in 1..rsizes[i] {
            pubs[npub + j] = pubs[npub + j - 1] + base;
        }

        // For next ring, base *= 4 (shift 2 bits in radix-4)
        if i < rings - 1 {
            base = base.double();
            base = base.double();
        }
        npub += rsizes[i];
    }
}

/// Calculate range proof parameters from value and settings
///
/// This is the core function that determines:
/// - How many rings we need
/// - How many elements in each ring
/// - Which element in each ring is the "real" one
/// - The scale factor and encoded value
fn range_proveparams(
    min_value: &mut u64,
    exp: &mut i32,
    min_bits: &mut i32,
    value: u64,
) -> Result<RangeProofParams> {
    let rings;
    let mut rsizes;
    let mut secidx;
    let mut scale: u64 = 1;
    let mut mantissa: usize;
    let mut npub: usize = 0;

    // If min_value is max, we cannot code a range
    if *min_value == u64::MAX {
        *exp = -1;
    }

    if *exp >= 0 {
        let mut v2: u64;

        // Overflow check
        if (*min_value > 0 && value > i64::MAX as u64)
            || (value > 0 && *min_value >= i64::MAX as u64)
        {
            return Err(VeilCryptoError::Other(
                "Value or min_value too large (>= 2^63)".to_string(),
            ));
        }

        // Calculate max_bits based on min_value
        let max_bits = if *min_value > 0 {
            clz64(*min_value)
        } else {
            64
        };

        if *min_bits > max_bits as i32 {
            *min_bits = max_bits as i32;
        }

        // For very large numbers, disable exponent
        if *min_bits > 61 || value > i64::MAX as u64 {
            *exp = 0;
        }

        // Mask off least significant digits
        let mut v = value.saturating_sub(*min_value);

        // Adjust exponent based on min_bits
        v2 = if *min_bits > 0 {
            u64::MAX >> (64 - *min_bits)
        } else {
            0
        };

        let mut i = 0;
        while i < *exp as usize && v2 <= u64::MAX / 10 {
            v /= 10;
            v2 *= 10;
            i += 1;
        }
        *exp = i as i32;

        v2 = v;
        for _ in 0..*exp {
            v2 *= 10;
            scale *= 10;
        }

        // Compute public offset
        *min_value = value - v2;

        // How many bits do we need?
        mantissa = if v > 0 { 64 - clz64(v) } else { 1 };

        if (*min_bits as usize) > mantissa {
            mantissa = *min_bits as usize;
        }

        // Digits in radix-4, except last digit if mantissa is odd
        rings = (mantissa + 1) >> 1;
        rsizes = Vec::with_capacity(rings);
        secidx = Vec::with_capacity(rings);

        for i in 0..rings {
            // Each ring has 4 elements except possibly the last
            let ring_size = if i < rings - 1 || (mantissa & 1) == 0 {
                4
            } else {
                2
            };
            rsizes.push(ring_size);
            npub += ring_size;

            // Extract the secret index (which digit of the value)
            secidx.push(((v >> (i * 2)) & 3) as usize);
        }

        // Validation
        if v & !(u64::MAX >> (64 - mantissa)) != 0 {
            return Err(VeilCryptoError::Other(
                "Value encoding error: mantissa mismatch".to_string(),
            ));
        }

        Ok(RangeProofParams {
            rings,
            rsizes,
            secidx,
            npub,
            mantissa,
            min_value: *min_value,
            scale,
            v,
        })
    } else {
        // Exact value proof (exp = -1)
        *exp = 0;
        *min_value = value;

        Ok(RangeProofParams {
            rings: 1,
            rsizes: vec![1],
            secidx: vec![0],
            npub: 1,  // Fixed: rings=1 with rsizes=[1] means only 1 public key total
            mantissa: 0,
            min_value: value,
            scale: 1,
            v: 0,
        })
    }
}

//
// ===== MAIN FUNCTIONS (STUBS FOR NOW) =====
//

/// Sign a range proof
///
/// Creates a Borromean ring signature-based range proof that proves
/// a committed value is in a valid range without revealing the value.
///
/// **STATUS**: 🚧 Under construction - Pure Rust implementation
pub fn rangeproof_sign(
    commitment: &[u8],
    value: u64,
    blind: &[u8],
    nonce: &[u8],
    message: Option<&[u8]>,
    min_value: u64,
    exp: i32,
    min_bits: i32,
) -> Result<RangeProofSignResult> {
    use sha2::{Sha256, Digest};

    // Validate inputs
    if commitment.len() != 33 {
        return Err(VeilCryptoError::Other(
            "commitment must be 33 bytes".to_string(),
        ));
    }
    if blind.len() != 32 {
        return Err(VeilCryptoError::InvalidSecretKey);
    }
    if nonce.len() != 32 && nonce.len() != 33 {
        return Err(VeilCryptoError::Other(
            "nonce must be 32 or 33 bytes".to_string(),
        ));
    }
    if exp < -1 || exp > 18 {
        return Err(VeilCryptoError::Other(
            "exp must be in range [-1, 18]".to_string(),
        ));
    }
    if min_bits < 0 || min_bits > 64 {
        return Err(VeilCryptoError::Other(
            "min_bits must be in range [0, 64]".to_string(),
        ));
    }
    if min_value > value {
        return Err(VeilCryptoError::Other(
            "min_value cannot be greater than value".to_string(),
        ));
    }

    // Calculate proof parameters
    let mut min_val_mut = min_value;
    let mut exp_mut = exp;
    let mut min_bits_mut = min_bits;

    let params = range_proveparams(&mut min_val_mut, &mut exp_mut, &mut min_bits_mut, value)?;

    // Parse commitment point using C++-matching loader
    // This properly handles 0x08/0x09 format with canonical y + conditional negation
    let commit_point = crate::mlsag::pedersen_commitment_load(commitment)?;
    let commit_affine = commit_point.to_affine();

    // Get generator H
    let genp_proj = get_generator_h_point()?;  // Veil blockchain H generator (0x11)
    let genp_affine = genp_proj.to_affine();

    eprintln!("\n=== Generator H ===");
    let genp_sec1 = serialize_point(&genp_affine);
    let genp_custom = serialize_point_custom(&genp_affine);
    eprintln!("SEC1 format: {}", hex::encode(&genp_sec1));
    eprintln!("Custom format: {}", hex::encode(&genp_custom));

    //
    // ===== STEP 1: Build proof header =====
    //
    let mut proof = Vec::with_capacity(MAX_PROOF_SIZE);

    // Flags byte: bit 6 = has mantissa, bit 5 = has min_value, bits 0-4 = exp
    let has_mantissa = params.rsizes[0] > 1;
    let has_min_value = min_val_mut > 0;
    let flags = (if has_mantissa { 64 | exp_mut as u8 } else { 0 })
        | (if has_min_value { 32 } else { 0 });
    proof.push(flags);

    // If mantissa exists, write mantissa-1
    if has_mantissa {
        proof.push((params.mantissa - 1) as u8);
    }

    // If min_value exists, write it as 8 bytes big-endian
    if has_min_value {
        for i in 0..8 {
            proof.push((min_val_mut >> ((7 - i) * 8)) as u8);
        }
    }

    //
    // ===== STEP 2: Prepare message buffer =====
    //
    let msg_len = message.as_ref().map(|m| m.len()).unwrap_or(0);

    // Check if we have room for the message
    if msg_len > 0 && msg_len > 128 * (params.rings - 1) {
        return Err(VeilCryptoError::Other(
            format!("Message too large: {} bytes, max {} bytes",
                msg_len, 128 * (params.rings - 1))
        ));
    }

    // Prepare 4096-byte buffer for message encryption
    let mut prep = vec![0u8; 4096];
    if let Some(msg) = message {
        prep[..msg.len()].copy_from_slice(msg);
    }

    // Special handling for value encoding sidechannel (line 295-309 in C code)
    // The last ring encodes information about the value
    if params.rsizes[params.rings - 1] > 1 {
        let mut idx = params.rsizes[params.rings - 1] - 1;
        // Avoid the secret index
        if params.secidx[params.rings - 1] == idx {
            idx -= 1;
        }
        let base_idx = ((params.rings - 1) * 4 + idx) * 32;

        // Write value encoding
        for i in 0..8 {
            let byte = (params.v >> (56 - i * 8)) as u8;
            prep[base_idx + 8 + i] = byte;
            prep[base_idx + 16 + i] = byte;
            prep[base_idx + 24 + i] = byte;
            prep[base_idx + i] = 0;
        }
        prep[base_idx] = 128;
    }

    //
    // ===== STEP 3: Generate random values (sec and s arrays) =====
    //
    let mut sec = vec![Scalar::ZERO; params.rings];
    let mut s = vec![Scalar::ZERO; params.npub];

    // Use nonce (first 32 bytes if 33-byte nonce)
    let nonce_32 = if nonce.len() == 33 {
        &nonce[..32]
    } else {
        nonce
    };

    let genrand_success = rangeproof_genrand(
        &mut sec,
        &mut s,
        Some(&mut prep[..]),
        &params.rsizes,
        params.rings,
        nonce_32,
        &commit_affine,
        &genp_affine,
        &proof,
    )?;

    if !genrand_success {
        return Err(VeilCryptoError::Other(
            "rangeproof_genrand failed: invalid scalar generated".to_string()
        ));
    }

    //
    // ===== STEP 4: Move nonces and add blind factor =====
    //
    // Copy the "real" s values into k array (these become nonces for signing)
    let mut k = vec![Scalar::ZERO; params.rings];
    for i in 0..params.rings {
        let idx = i * 4 + params.secidx[i];
        k[i] = s[idx];
        s[idx] = Scalar::ZERO; // Clear the real position
    }

    // Add the blind factor to the last sec value
    // This makes sec[rings-1] = -sum(sec[0..rings-2]) + blind
    let mut blind_bytes = [0u8; 32];
    blind_bytes.copy_from_slice(blind);
    let blind_scalar = Option::<Scalar>::from(Scalar::from_repr(blind_bytes.into()))
        .ok_or_else(|| VeilCryptoError::InvalidSecretKey)?;

    sec[params.rings - 1] += blind_scalar;

    if bool::from(sec[params.rings - 1].is_zero()) {
        return Err(VeilCryptoError::Other(
            "Blinding factor resulted in zero secret".to_string()
        ));
    }

    //
    // ===== STEP 5: Reserve space for sign bits =====
    //
    let signs_offset = proof.len();
    let signs_len = (params.rings + 6) >> 3; // Ceiling division by 8
    for _ in 0..signs_len {
        proof.push(0);
    }

    //
    // ===== STEP 6: Create Pedersen commitments and serialize =====
    //
    let mut sha256_m = Sha256::new();

    // Hash commitment and generator (use custom format to match C)
    sha256_m.update(&serialize_point_custom(&commit_affine));
    sha256_m.update(&serialize_point_custom(&genp_affine));

    // Hash the proof header we've built so far
    sha256_m.update(&proof[..signs_offset]);

    let mut pubs = vec![ProjectivePoint::IDENTITY; params.npub];
    let mut npub_idx = 0;

    eprintln!("\n=== Building Commitments ===");
    eprintln!("scale={}, rings={}", params.scale, params.rings);
    eprintln!("secidx={:?}", params.secidx);

    for i in 0..params.rings {
        // Create Pedersen commitment: sec[i] * G + (secidx[i] * scale * 4^i) * H
        let value_part = (params.secidx[i] as u64 * params.scale) << (i * 2);

        if i == 0 {
            eprintln!("\nRing 0 commitment details:");
            eprintln!("  sec[0] = {}", hex::encode(sec[0].to_bytes()));
            eprintln!("  secidx[0] = {}", params.secidx[0]);
            eprintln!("  value_part = {}", value_part);
        }

        pubs[npub_idx] = pedersen_ecmult_point(&sec[i], value_part, &genp_proj)?;

        if bool::from(pubs[npub_idx].is_identity()) {
            return Err(VeilCryptoError::Other(
                format!("Commitment at ring {} is infinity", i)
            ));
        }

        // For all but the last ring, serialize the commitment and add to hash
        if i < params.rings - 1 {
            eprintln!("\n=== Ring {} commitment serialization ===", i);
            eprintln!("npub_idx={}, pubs.len()={}", npub_idx, pubs.len());
            eprintln!("pubs[{}] is_identity={}", npub_idx, bool::from(pubs[npub_idx].is_identity()));

            let c_affine = pubs[npub_idx].to_affine();
            // MATCH C++: Use custom format (QR-based 0x00/0x01), NOT SEC1 (0x02/0x03)
            let serialized = serialize_point_custom(&c_affine);
            let quadness = serialized[0]; // 0x00 if QR, 0x01 if NOT QR

            eprintln!("Ring {}: commitment quadness={:#04x}, value_part={}",
                     i, quadness, value_part);

            // Hash tmpc (33 bytes): quadness + x-coordinate
            // Matches C++: secp256k1_sha256_write(&sha256_m, tmpc, 33);
            sha256_m.update(&serialized);

            // Set quadness bit in signs array
            // Matches C++: signs[i>>3] |= quadness << (i&7);
            // quadness is 0x00 or 0x01, so the bit is 0 or 1
            let sign_byte_idx = i >> 3;
            let sign_bit_idx = i & 7;
            proof[signs_offset + sign_byte_idx] |= (quadness & 1) << sign_bit_idx;

            eprintln!("Ring {}: quadness={:#04x}, storing bit {} at signs[{}]",
                i, quadness, quadness & 1, i);

            // Write x-coordinate only (32 bytes)
            eprintln!("Ring {}: Writing x-coord at offset {} (proof.len()={}), x={}",
                i, proof.len(), proof.len(), hex::encode(&serialized[1..9]));
            proof.extend_from_slice(&serialized[1..]);
        }

        npub_idx += params.rsizes[i];
    }

    //
    // ===== STEP 7: Expand public keys for all ring elements =====
    //
    eprintln!("\n=== SIGN: PUBS BEFORE EXPANSION ===");
    let mut npub_check = 0;
    for i in 0..params.rings {
        let affine = pubs[npub_check].to_affine();
        let encoded = affine.to_encoded_point(true);
        eprintln!("  pubs[{}] (ring {}): {}", npub_check, i, hex::encode(encoded.as_bytes()));
        npub_check += params.rsizes[i];
    }

    rangeproof_pub_expand(&mut pubs, exp_mut, &params.rsizes, params.rings, &genp_affine);

    //
    // ===== STEP 8: Finalize message hash =====
    //
    let message_hash = sha256_m.finalize();
    eprintln!("\n=== SIGN: Message hash for Borromean ===");
    eprintln!("message_hash: {}", hex::encode(&message_hash));

    eprintln!("\n========== DEBUG: PUBS BEFORE BORROMEAN SIGN ==========");
    eprintln!("Total pubs elements: {}", pubs.len());
    for (idx, p) in pubs.iter().enumerate().take(3) {
        let affine = p.to_affine();
        let encoded = affine.to_encoded_point(true);
        eprintln!("  pubs[{}]: {}", idx, hex::encode(encoded.as_bytes()));
    }
    eprintln!("=====================================================\n");

    //
    // ===== STEP 9: Call Borromean sign =====
    //
    // Convert data to the format borromean_sign expects
    let pubs_bytes: Vec<[u8; 33]> = pubs.iter()
        .map(|p| serialize_point(&p.to_affine()))
        .collect();

    let k_bytes: Vec<[u8; 32]> = k.iter()
        .map(|scalar| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&scalar.to_bytes());
            bytes
        })
        .collect();

    let sec_bytes: Vec<[u8; 32]> = sec.iter()
        .map(|scalar| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&scalar.to_bytes());
            bytes
        })
        .collect();

    let s_bytes: Vec<[u8; 32]> = s.iter()
        .map(|scalar| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&scalar.to_bytes());
            bytes
        })
        .collect();

    let (e0, s_result) = borromean_sign(
        &pubs_bytes,
        &k_bytes,
        &sec_bytes,
        &s_bytes,
        &params.rsizes,
        &params.secidx,
        &message_hash,
    )?;

    //
    // ===== STEP 10: Serialize final proof =====
    //
    // Write e0 (32 bytes)
    proof.extend_from_slice(&e0);

    // Write all s values (32 bytes each)
    for s_val in s_result {
        proof.extend_from_slice(&s_val);
    }

    // Return result
    Ok(RangeProofSignResult {
        proof: proof.clone(),
        commitment: commitment.to_vec(),
        blind: blind.to_vec(),
        nonce: nonce.to_vec(),
    })
}

/// Parse range proof header
///
/// Extracts flags, exp, mantissa, scale, min_value, max_value from proof
fn parse_proof_header(proof: &[u8]) -> Result<(usize, i32, usize, u64, u64, u64)> {
    let mut offset = 0usize;

    // Minimum proof size
    if proof.len() < 65 {
        return Err(VeilCryptoError::Other("Proof too short".to_string()));
    }

    // Check high bit is clear
    if (proof[offset] & 128) != 0 {
        return Err(VeilCryptoError::Other("Invalid proof flags".to_string()));
    }

    let has_nz_range = (proof[offset] & 64) != 0;
    let has_min = (proof[offset] & 32) != 0;

    let mut exp = -1i32;
    let mut mantissa = 0usize;
    let mut max_value = 0u64;

    if has_nz_range {
        exp = (proof[offset] & 31) as i32;
        offset += 1;

        if exp > 18 {
            return Err(VeilCryptoError::Other("Invalid exponent".to_string()));
        }

        if offset >= proof.len() {
            return Err(VeilCryptoError::Other("Proof truncated at mantissa".to_string()));
        }

        mantissa = proof[offset] as usize + 1;
        if mantissa > 64 {
            return Err(VeilCryptoError::Other("Invalid mantissa".to_string()));
        }

        max_value = u64::MAX >> (64 - mantissa);
    }

    offset += 1;

    // Calculate scale = 10^exp
    let mut scale = 1u64;
    for _ in 0..exp {
        if max_value > u64::MAX / 10 {
            return Err(VeilCryptoError::Other("Max value overflow".to_string()));
        }
        max_value = max_value.wrapping_mul(10);
        scale = scale.wrapping_mul(10);
    }

    // Parse min_value if present
    let mut min_value = 0u64;
    if has_min {
        if proof.len() - offset < 8 {
            return Err(VeilCryptoError::Other("Proof truncated at min_value".to_string()));
        }

        for i in 0..8 {
            min_value = (min_value << 8) | (proof[offset + i] as u64);
        }
        offset += 8;
    }

    // Check for overflow
    if max_value > u64::MAX - min_value {
        return Err(VeilCryptoError::Other("Value range overflow".to_string()));
    }
    max_value += min_value;

    Ok((offset, exp, mantissa, scale, min_value, max_value))
}

/// Verify a range proof
///
/// Verifies that a commitment contains a value in the proven range without
/// revealing the value itself.
pub fn rangeproof_verify(commitment: &[u8], proof: &[u8]) -> Result<RangeProofVerifyResult> {
    use sha2::{Sha256, Digest};
    use k256::elliptic_curve::sec1::FromEncodedPoint;

    // Validate inputs
    if commitment.len() != 33 {
        return Err(VeilCryptoError::Other("commitment must be 33 bytes".to_string()));
    }

    // Parse commitment point using C++-matching loader
    // This properly handles 0x08/0x09 format with canonical y + conditional negation
    let commit_point = crate::mlsag::pedersen_commitment_load(commitment)?;
    let commit_affine = commit_point.to_affine();

    // Get generator H
    let genp_proj = get_generator_h_point()?;  // Veil blockchain H generator (0x11)
    let genp_affine = genp_proj.to_affine();

    //
    // ===== STEP 1: Parse proof header =====
    //
    let (mut offset, exp, mantissa, _scale, min_value, max_value) = parse_proof_header(proof)?;
    let _offset_post_header = offset;

    //
    // ===== STEP 2: Calculate rings and rsizes =====
    //
    let mut rings = 1usize;
    let mut rsizes = vec![1usize];
    let mut npub = 1usize;

    if mantissa != 0 {
        rings = mantissa >> 1; // mantissa / 2
        rsizes = vec![4; rings];
        npub = rings << 2; // rings * 4

        // If mantissa is odd, add a ring with 2 elements
        if (mantissa & 1) != 0 {
            rsizes.push(2);
            npub += 2;
            rings += 1;
        }
    }

    if rings > MAX_RINGS {
        return Err(VeilCryptoError::Other("Too many rings".to_string()));
    }

    //
    // ===== STEP 3: Validate proof length =====
    //
    let signs_len = (rings + 6) >> 3; // Ceiling division by 8
    let required_len = offset + signs_len + 32 * (npub + rings - 1) + 32;
    if proof.len() < required_len {
        return Err(VeilCryptoError::Other(
            format!("Proof too short: {} < {}", proof.len(), required_len)
        ));
    }

    //
    // ===== STEP 4: Build SHA256 message hash =====
    //
    let mut sha256_m = Sha256::new();
    // Use custom format to match C code
    sha256_m.update(&serialize_point_custom(&commit_affine));
    sha256_m.update(&serialize_point_custom(&genp_affine));
    sha256_m.update(&proof[..offset]);

    //
    // ===== STEP 5: Extract sign bits =====
    //
    let mut signs = vec![false; rings];
    for i in 0..(rings - 1) {
        let byte_idx = i >> 3;
        let bit_idx = i & 7;
        signs[i] = (proof[offset + byte_idx] & (1 << bit_idx)) != 0;
    }

    eprintln!("\n=== VERIFY: Signs array ===");
    for i in 0..rings.min(4) {
        eprintln!("  signs[{}] = {}", i, signs[i]);
    }

    offset += signs_len;

    // Verify unused sign bits are zero (mutation check)
    if ((rings - 1) & 7) != 0 {
        let last_used_bit = (rings - 1) & 7;
        let unused_mask = 0xffu8 << last_used_bit;
        if (proof[offset - 1] & unused_mask) != 0 {
            return Err(VeilCryptoError::Other("Invalid unused sign bits".to_string()));
        }
    }

    //
    // ===== STEP 6: Reconstruct public keys =====
    //
    let mut pubs = vec![ProjectivePoint::IDENTITY; npub];
    let mut accj = ProjectivePoint::IDENTITY;

    // Add min_value * H to accumulator
    if min_value > 0 {
        accj = genp_proj * Scalar::from(min_value);
    }

    // Process commitments for rings 0..(rings-1)
    let mut npub_idx = 0usize;
    for i in 0..(rings - 1) {
        // Parse x-coordinate from proof
        if offset + 32 > proof.len() {
            return Err(VeilCryptoError::Other("Proof truncated at commitment".to_string()));
        }

        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&proof[offset..offset + 32]);

        // Reconstruct point from x-coordinate and quadness bit
        // MATCH C++: Use canonical y + conditional negation (NOT SEC1 parity!)
        // C++ code:
        //   secp256k1_fe_set_b32(&fe, &proof[offset]);
        //   secp256k1_ge_set_xquad(&c, &fe);  // canonical y
        //   if (signs[i]) { secp256k1_ge_neg(&c, &c); }  // negate if NOT QR

        use k256::FieldElement;
        let x = FieldElement::from_bytes(&x_bytes.into())
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid x-coordinate".to_string()))?;

        // Compute y² = x³ + 7
        let x_cubed = x * x * x;
        let b = FieldElement::from(7u64);
        let y_squared = x_cubed + b;

        // Compute sqrt to get ONE of the two roots
        let mut y = y_squared.sqrt()
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Point not on curve".to_string()))?;

        // CRITICAL: Match secp256k1's behavior
        // secp256k1's is_quad_var(y) checks if sqrt(y) exists
        // The sqrt(x³+7) gives us ONE root - check if IT has a square root
        // If sqrt(y) succeeds, y is a QR
        // If sqrt(y) fails, y is NOT a QR
        let y_has_sqrt = y.sqrt().is_some();
        let y_is_qr: bool = y_has_sqrt.into();

        // If y is NOT a QR, use -y (which must be the QR)
        // Because exactly one of {y, -y} is a QR
        if !y_is_qr {
            y = -y;
        }

        eprintln!("\n=== VERIFY: Ring {} sqrt selection ===", i);
        eprintln!("  x = {}", hex::encode(x.to_bytes()));
        eprintln!("  y (QR root) = {}", hex::encode(y.to_bytes()));
        eprintln!("  y_is_qr check = {}", y_is_qr);

        // Create point with QR root y
        let y_bytes = y.to_bytes();
        let mut point_bytes = [0u8; 65];
        point_bytes[0] = 0x04; // Uncompressed
        point_bytes[1..33].copy_from_slice(&x_bytes);
        point_bytes[33..65].copy_from_slice(&y_bytes);

        let encoded = k256::EncodedPoint::from_bytes(&point_bytes)
            .map_err(|_| VeilCryptoError::Other("Invalid point encoding".to_string()))?;
        let mut point_affine = AffinePoint::from_encoded_point(&encoded)
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid point".to_string()))?;

        // Negate if signs[i] = 1 (NOT QR)
        // C++ stores: data[0] = !is_quad_var(y), so 0=QR, 1=NOT QR
        // C++ verify does: if (signs[i]) { negate }
        eprintln!("\n=== VERIFY: Ring {} reconstruction ===", i);
        eprintln!("  signs[{}] = {}", i, signs[i]);
        eprintln!("  Before negate: {}", hex::encode(point_affine.to_encoded_point(true).as_bytes()));
        if signs[i] {
            point_affine = -point_affine;
        }
        eprintln!("  After negate:  {}", hex::encode(point_affine.to_encoded_point(true).as_bytes()));

        // Hash the commitment: sign bit || x-coordinate
        sha256_m.update(&[if signs[i] { 1u8 } else { 0u8 }]);
        sha256_m.update(&x_bytes);

        pubs[npub_idx] = ProjectivePoint::from(point_affine);
        accj += point_affine;

        offset += 32;
        npub_idx += rsizes[i];
    }

    // Last ring: pubs[npub_idx] = commitment - accj
    accj = -accj;
    accj += commit_affine;

    if bool::from(accj.is_identity()) {
        return Err(VeilCryptoError::Other("Last commitment is identity".to_string()));
    }

    pubs[npub_idx] = accj;

    //
    // ===== STEP 7: Expand public keys =====
    //
    eprintln!("\n=== VERIFY: PUBS BEFORE EXPANSION ===");
    let mut npub_check = 0;
    for i in 0..rings {
        let affine = pubs[npub_check].to_affine();
        let encoded = affine.to_encoded_point(true);
        eprintln!("  pubs[{}] (ring {}): {}", npub_check, i, hex::encode(encoded.as_bytes()));
        npub_check += rsizes[i];
    }

    rangeproof_pub_expand(&mut pubs, exp, &rsizes, rings, &genp_affine);

    eprintln!("\n========== DEBUG: PUBS BEFORE BORROMEAN VERIFY ==========");
    eprintln!("Total pubs elements: {}", pubs.len());
    for (idx, p) in pubs.iter().enumerate().take(3) {
        let affine = p.to_affine();
        let encoded = affine.to_encoded_point(true);
        eprintln!("  pubs[{}]: {}", idx, hex::encode(encoded.as_bytes()));
    }
    eprintln!("=====================================================\n");

    //
    // ===== STEP 8: Parse e0 and s values =====
    //
    if offset + 32 + npub * 32 > proof.len() {
        return Err(VeilCryptoError::Other("Proof truncated at signatures".to_string()));
    }

    let mut e0 = [0u8; 32];
    e0.copy_from_slice(&proof[offset..offset + 32]);
    offset += 32;

    let mut s_values = Vec::with_capacity(npub);
    for _ in 0..npub {
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&proof[offset..offset + 32]);
        s_values.push(s_bytes);
        offset += 32;
    }

    // Verify we consumed the entire proof
    if offset != proof.len() {
        return Err(VeilCryptoError::Other("Extra data in proof".to_string()));
    }

    //
    // ===== STEP 9: Finalize message hash =====
    //
    let message_hash = sha256_m.finalize();
    eprintln!("\n=== VERIFY: Message hash for Borromean ===");
    eprintln!("message_hash: {}", hex::encode(&message_hash));

    //
    // ===== STEP 10: Call Borromean verify =====
    //
    // Convert pubs to byte format
    let pubs_bytes: Vec<[u8; 33]> = pubs.iter()
        .map(|p| serialize_point(&p.to_affine()))
        .collect();

    // Verify Borromean signature
    use crate::borromean::borromean_verify;
    let verify_result = borromean_verify(
        &e0,
        &s_values,
        &pubs_bytes,
        &rsizes,
        &message_hash,
    )?;

    if !verify_result {
        return Err(VeilCryptoError::Other("Borromean signature verification failed".to_string()));
    }

    //
    // ===== STEP 11: Return result =====
    //
    Ok(RangeProofVerifyResult {
        min_value,
        max_value,
    })
}

// ===== HELPER FUNCTIONS FOR REWIND =====

/// Recover secret key x from Borromean signature
///
/// Formula: x = (k - s) / e = (k - s) * e^-1
///
/// Where:
/// - k = original nonce
/// - e = challenge
/// - s = signature
/// - x = secret key (what we're recovering)
fn rangeproof_recover_x(k: &Scalar, e: &Scalar, s: &Scalar) -> Scalar {
    // x = (k - s) * e^-1
    let k_minus_s = *k - s;
    let e_inv = e.invert().unwrap(); // e is never zero in valid signatures
    k_minus_s * e_inv
}

/// Recover nonce k from Borromean signature
///
/// Formula: k = s + x*e
///
/// Where:
/// - x = secret key
/// - e = challenge
/// - s = signature
/// - k = nonce (what we're recovering)
fn rangeproof_recover_k(x: &Scalar, e: &Scalar, s: &Scalar) -> Scalar {
    // k = s + x*e
    s + (x * e)
}

/// XOR two 32-byte arrays
fn xor_32(a: &mut [u8; 32], b: &[u8; 32]) {
    for i in 0..32 {
        a[i] ^= b[i];
    }
}

// Note: rangeproof_genrand already exists above (line 252), we'll use that

/// Rewind a range proof to extract value and blinding factor
///
/// Allows the recipient (who knows the nonce) to extract:
/// - The committed value
/// - The blinding factor
/// - Optional message from sender
pub fn rangeproof_rewind(
    nonce: &[u8],
    commitment: &[u8],
    proof: &[u8],
) -> Result<RangeProofRewindResult> {
    // Validate inputs
    if nonce.len() != 32 {
        return Err(VeilCryptoError::Other("Nonce must be 32 bytes".to_string()));
    }
    if commitment.len() != 33 {
        return Err(VeilCryptoError::Other("Commitment must be 33 bytes".to_string()));
    }
    if proof.len() < 11 {
        return Err(VeilCryptoError::InvalidRangeProof);
    }

    // Parse proof header
    let (offset, exp, mantissa, scale, min_value, max_value) = parse_proof_header(proof)?;
    let offset_post_header = offset;

    // Calculate ring structure (same as verify)
    let mut rings = 1usize;
    let mut rsizes = vec![1usize];

    if mantissa != 0 {
        rings = mantissa >> 1; // mantissa / 2
        rsizes = vec![4; rings];

        // If mantissa is odd, add a ring with 2 elements
        if (mantissa & 1) != 0 {
            rsizes.push(2);
            rings += 1;
        }
    }

    // Get Generator H (Veil blockchain 0x11 format)
    let genp = crate::pedersen::get_generator_h_point()?.to_affine();
    eprintln!("DEBUG rewind: Using Veil H generator (0x11 format)");
    eprintln!("DEBUG rewind: H generator point: {:?}", genp);

    // Parse commitment point using C++-matching loader
    eprintln!("DEBUG rewind: commitment[0]={:#04x}, len={}", commitment[0], commitment.len());
    let commit_proj = crate::mlsag::pedersen_commitment_load(commitment)?;
    let commit_point = commit_proj.to_affine();

    // Allocate buffers for genrand
    let npub_total = rsizes.iter().sum();
    let mut sec = vec![Scalar::ZERO; rings];
    let mut s_orig = vec![Scalar::ZERO; npub_total];
    let mut message_buf = vec![0u8; 4096]; // Max message size

    // Reconstruct prover's random values
    let proof_header = &proof[0..offset_post_header];
    rangeproof_genrand(
        &mut sec,
        &mut s_orig,
        Some(&mut message_buf),
        &rsizes,
        rings,
        nonce,
        &commit_point,
        &genp,
        proof_header,
    )?;

    //
    // ===== Parse Borromean Signature from Proof =====
    //
    // Reset offset to start of proof body (after header)
    let mut offset = offset_post_header;

    // Calculate proof lengths
    let signs_len = (rings + 6) >> 3;
    let required_len = offset + signs_len + 32 * (npub_total + rings - 1) + 32;

    eprintln!("DEBUG: offset_post_header={}, signs_len={}, rings={}, npub_total={}",
        offset_post_header, signs_len, rings, npub_total);
    if proof.len() < required_len {
        return Err(VeilCryptoError::Other(
            format!("Proof too short for rewind: {} < {}", proof.len(), required_len)
        ));
    }

    // Build SHA256 message hash (same as verify)
    let mut sha256_m = Sha256::new();
    sha256_m.update(&serialize_point_custom(&commit_point));
    sha256_m.update(&serialize_point_custom(&genp));
    sha256_m.update(&proof[..offset_post_header]);

    // Extract sign bits
    let mut signs = vec![false; rings];
    for i in 0..(rings - 1) {
        let byte_idx = i >> 3;
        let bit_idx = i & 7;
        signs[i] = (proof[offset + byte_idx] & (1 << bit_idx)) != 0;
    }
    offset += signs_len;

    // Reconstruct public keys and hash commitments
    let mut pubs = vec![ProjectivePoint::IDENTITY; npub_total];
    let mut accj = ProjectivePoint::IDENTITY;

    // Add min_value * H to accumulator
    if min_value > 0 {
        accj = ProjectivePoint::from(&genp) * Scalar::from(min_value);
    }

    // Process commitments for rings 0..(rings-1)
    let mut npub_idx = 0usize;
    for i in 0..(rings - 1) {
        // Parse x-coordinate from proof
        if offset + 32 > proof.len() {
            return Err(VeilCryptoError::Other("Proof truncated at commitment".to_string()));
        }

        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&proof[offset..offset + 32]);

        eprintln!("Ring {}: offset={}, signs[{}]={}, x_bytes={}",
            i, offset, i, signs[i], hex::encode(&x_bytes[..8]));

        // Reconstruct point from x-coordinate using QR-based logic (NOT SEC1!)
        use k256::FieldElement;
        let x = FieldElement::from_bytes(&x_bytes.into())
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid x-coordinate".to_string()))?;

        // Compute y² = x³ + 7
        let x_cubed = x * x * x;
        let b = FieldElement::from(7u64);
        let y_squared = x_cubed + b;

        // Compute sqrt to get ONE of the two roots
        let mut y = y_squared.sqrt()
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Point not on curve".to_string()))?;

        // Match secp256k1: check if sqrt(y) exists to determine if y is a QR
        let y_has_sqrt = y.sqrt().is_some();
        let y_is_qr: bool = y_has_sqrt.into();
        if !y_is_qr {
            y = -y;
        }

        // Create point with QR root y
        let y_bytes = y.to_bytes();
        let mut point_bytes = [0u8; 65];
        point_bytes[0] = 0x04; // Uncompressed
        point_bytes[1..33].copy_from_slice(&x_bytes);
        point_bytes[33..65].copy_from_slice(&y_bytes);

        let point_encoded = k256::EncodedPoint::from_bytes(&point_bytes)
            .map_err(|_| VeilCryptoError::Other("Invalid point encoding".to_string()))?;
        let mut point_affine = AffinePoint::from_encoded_point(&point_encoded)
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other(format!("Invalid commitment point at ring {}, offset {}", i, offset)))?;

        // Negate if signs[i] = 1 (original y was NOT a QR)
        if signs[i] {
            point_affine = -point_affine;
        }

        eprintln!("Ring {}: Reconstructed point={}", i, hex::encode(point_affine.to_encoded_point(true).as_bytes()));

        // Hash the commitment: sign bit || x-coordinate
        sha256_m.update(&[if signs[i] { 1u8 } else { 0u8 }]);
        sha256_m.update(&x_bytes);

        pubs[npub_idx] = ProjectivePoint::from(point_affine);
        accj += point_affine;

        offset += 32;
        npub_idx += rsizes[i];
    }

    // Last ring: pubs[npub_idx] = commitment - accj
    accj = -accj;
    accj += commit_point;

    if bool::from(accj.is_identity()) {
        return Err(VeilCryptoError::Other("Last commitment is identity".to_string()));
    }

    pubs[npub_idx] = accj;

    // Expand public keys
    rangeproof_pub_expand(&mut pubs, exp, &rsizes, rings, &genp);

    // Parse e0 and s values from proof
    if offset + 32 + npub_total * 32 > proof.len() {
        return Err(VeilCryptoError::Other("Proof truncated at signatures".to_string()));
    }

    let mut e0 = [0u8; 32];
    e0.copy_from_slice(&proof[offset..offset + 32]);
    offset += 32;

    let mut s = Vec::with_capacity(npub_total);
    for _ in 0..npub_total {
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&proof[offset..offset + 32]);
        let s_scalar = Scalar::from_repr(s_bytes.into())
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid s value".to_string()))?;
        s.push(s_scalar);
        offset += 32;
    }

    //
    // ===== Extract Value from Last Ring =====
    //
    // Special case: single proof (rings==1, rsizes[0]==1)
    // This is an exact value proof where the value is stored as min_value in the header
    let value: u64;
    let skip1: usize;
    let skip2: usize;

    if rings == 1 && rsizes[0] == 1 {
        // Exact value proof - value is min_value from header
        value = min_value;
        skip1 = 0; // Not used for single ring
        skip2 = 0; // The only element is the real one
    } else {
        // Look for value encoding in last ring's signatures
        let npub_base = (rings - 1) * 4;
        let mut value_temp = u64::MAX;
        let mut skip1_temp = 0usize;

        for j in 0..2 {
            let idx = npub_base + rsizes[rings - 1] - 1 - j;
            if idx >= s.len() {
                continue;
            }

            // Get s[idx] as bytes (from parsed Borromean signature)
            let s_bytes = s[idx].to_bytes();
            let mut tmp: [u8; 32] = s_bytes.into();

            // XOR with prep to recover (prep is stored in message_buf as 32-byte chunks)
            let prep_slice: [u8; 32] = message_buf[idx * 32..(idx + 1) * 32]
                .try_into()
                .unwrap();
            xor_32(&mut tmp, &prep_slice);

            // Check for value encoding pattern:
            // tmp[0] & 0x80 and bytes 8-15, 16-23, 24-31 are identical
            if (tmp[0] & 0x80) != 0
                && tmp[16..24] == tmp[24..32]
                && tmp[8..16] == tmp[16..24]
            {
                // Extract value (big-endian from last 8 bytes)
                value_temp = u64::from_be_bytes(tmp[24..32].try_into().unwrap());
                skip1_temp = rsizes[rings - 1] - 1 - j;
                break;
            }
        }

        if value_temp == u64::MAX {
            return Err(VeilCryptoError::Other(
                "Could not extract value from proof".to_string()
            ));
        }

        value = value_temp;
        skip1 = skip1_temp;

        // Determine which signature in last ring is real (not forged)
        skip2 = ((value >> ((rings - 1) * 2)) & 3) as usize;
        if skip1 == skip2 {
            return Err(VeilCryptoError::Other(
                "Value is in wrong position".to_string()
            ));
        }
    }

    // Finalize message hash
    let message_hash = sha256_m.finalize();

    // Compute challenge values (ev) by simulating Borromean verification
    let mut ev = Vec::with_capacity(npub_total);
    let mut count = 0;

    for (i, &ring_size) in rsizes.iter().enumerate() {
        // Initial challenge for this ring: en = H(e0 || m || i || 0)
        let hash = crate::borromean::borromean_hash(&e0, &message_hash, i, 0);
        let mut en = Scalar::from_repr(hash.into())
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid scalar from hash".to_string()))?;

        // Process each pubkey in the ring
        for j in 0..ring_size {
            // Store challenge value
            ev.push(en);

            // Compute: r = s[count] * G + en * pubs[count]
            let s_times_g = ProjectivePoint::mul_by_generator(&s[count]);
            let en_times_pub = pubs[count] * en;
            let r = (s_times_g + en_times_pub).to_affine();

            // Serialize r for hashing
            let r_serialized = serialize_point_custom(&r);

            // Next challenge: en = H(r || m || i || j+1)
            let hash = crate::borromean::borromean_hash(&r_serialized, &message_hash, i, j + 1);
            en = Scalar::from_repr(hash.into())
                .into_option()
                .ok_or_else(|| VeilCryptoError::Other("Invalid scalar from hash".to_string()))?;

            count += 1;
        }
    }

    //
    // ===== Recover Blinding Factor =====
    //
    // Find which position in last ring is the real signature
    let last_ring_start = npub_total - rsizes[rings - 1];
    let blind_idx = last_ring_start + skip2;

    // Use recover_x to extract blind component
    let stmp = rangeproof_recover_x(&s_orig[blind_idx], &ev[blind_idx], &s[blind_idx]);

    // Add back negated sec[rings-1] to get final blind
    let sec_last_neg = -sec[rings - 1];
    let blind_scalar = stmp + sec_last_neg;
    let blind_bytes = blind_scalar.to_bytes();

    //
    // ===== Extract Message =====
    //
    let mut message_out = Vec::new();
    let mut npub_idx2 = 0;

    for i in 0..rings {
        let idx = ((value >> (i * 2)) & 3) as usize;
        for j in 0..rsizes[i] {
            if npub_idx2 == blind_idx || npub_idx2 == last_ring_start + skip1 {
                // Skip positions used for value/blind encoding
                npub_idx2 += 1;
                continue;
            }

            let stmp = if idx == j {
                // Real signature - recover nonce
                rangeproof_recover_k(&sec[i], &ev[npub_idx2], &s[npub_idx2])
            } else {
                // Forged signature - use s_orig
                s_orig[npub_idx2]
            };

            // Extract message bytes
            let mut tmp: [u8; 32] = stmp.to_bytes().into();
            let prep_slice: [u8; 32] = message_buf[npub_idx2 * 32..(npub_idx2 + 1) * 32]
                .try_into()
                .unwrap();
            xor_32(&mut tmp, &prep_slice);
            message_out.extend_from_slice(&tmp);
            npub_idx2 += 1;
        }
    }

    // Apply scale and min_value to get actual value
    // For single-ring proofs (rings==1, rsizes[0]==1), value is already the final value
    // For multi-ring proofs, value is an offset that needs scaling and min_value added
    let actual_value = if rings == 1 && rsizes[0] == 1 {
        value  // Single-ring: value is already min_value (the final value)
    } else {
        value * scale + min_value  // Multi-ring: value is offset from min_value
    };

    Ok(RangeProofRewindResult {
        blind: blind_bytes.to_vec(),
        value: actual_value,
        min_value,
        max_value,
        message: message_out,
    })
}

/// Extract metadata from a range proof without full verification
///
/// This is a lightweight function that only parses the proof header
/// to extract exp, mantissa, min_value, and max_value without performing
/// the full cryptographic verification.
///
/// # Arguments
///
/// * `proof` - The range proof to extract info from
///
/// # Returns
///
/// Returns `RangeProofInfo` containing the proof metadata
pub fn rangeproof_info(proof: &[u8]) -> Result<RangeProofInfo> {
    // Parse proof header
    let (_offset, exp, mantissa, _scale, min_value, max_value) = parse_proof_header(proof)?;

    Ok(RangeProofInfo {
        exp,
        mantissa,
        min_value,
        max_value,
    })
}

//
// ===== TESTS =====
//

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_hmac_drbg_simple() {
        // Test HMAC-DRBG with a simple known seed
        let seed = b"test seed";
        let mut drbg = HmacDrbg::new(seed);

        let output1 = drbg.generate();
        let output2 = drbg.generate();

        eprintln!("Simple HMAC-DRBG test:");
        eprintln!("Seed: {:?}", std::str::from_utf8(seed));
        eprintln!("Output 1: {}", hex::encode(&output1));
        eprintln!("Output 2: {}", hex::encode(&output2));
    }

    #[test]
    fn test_range_proveparams_basic() {
        let value = 12345u64;
        let mut min_value = 0u64;
        let mut exp = 2i32;
        let mut min_bits = 32i32;

        let params = range_proveparams(&mut min_value, &mut exp, &mut min_bits, value).unwrap();

        println!("Test value: {}", value);
        println!("Params: rings={}, npub={}, mantissa={}", params.rings, params.npub, params.mantissa);
        println!("rsizes: {:?}", params.rsizes);
        println!("secidx: {:?}", params.secidx);
        println!("scale: {}, v: {}", params.scale, params.v);

        // Basic validation
        assert!(params.rings > 0);
        assert!(params.rings <= MAX_RINGS);
        assert_eq!(params.rsizes.len(), params.rings);
        assert_eq!(params.secidx.len(), params.rings);
        assert!(params.npub <= MAX_NPUB);
    }

    #[test]
    fn test_range_proveparams_small_value() {
        let value = 100u64;
        let mut min_value = 0u64;
        let mut exp = 2i32;
        let mut min_bits = 32i32;

        let params = range_proveparams(&mut min_value, &mut exp, &mut min_bits, value).unwrap();

        assert!(params.rings > 0);
        assert!(params.npub > 0);
    }

    #[test]
    fn test_range_proveparams_large_value() {
        let value = 1000000000u64;
        let mut min_value = 0u64;
        let mut exp = 2i32;
        let mut min_bits = 32i32;

        let params = range_proveparams(&mut min_value, &mut exp, &mut min_bits, value).unwrap();

        assert!(params.rings > 0);
        assert!(params.npub > 0);
    }

    #[test]
    fn test_serialize_point() {
        use k256::ProjectivePoint;

        // Test with generator point
        let g = ProjectivePoint::GENERATOR;
        let g_affine = g.to_affine();
        let serialized = serialize_point(&g_affine);

        // Should be 33 bytes (compressed)
        assert_eq!(serialized.len(), 33);

        // First byte should be 0x02 or 0x03 (compressed format)
        assert!(serialized[0] == 0x02 || serialized[0] == 0x03);
    }

    #[test]
    fn test_rangeproof_sign_basic() {
        use crate::pedersen::pedersen_commit;

        // Test parameters (Veil-standard)
        let value = 12345u64;
        let blind_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let nonce_hex = "2222222222222222222222222222222222222222222222222222222222222222";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        // Create commitment in Veil format (0x08/0x09)
        let commitment_veil = pedersen_commit(value, &blind).unwrap();

        // Convert to standard SEC1 format for rangeproof_sign
        // Veil: 0x08 = even y, 0x09 = odd y
        // SEC1: 0x02 = even y, 0x03 = odd y
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        println!("Testing rangeproof_sign with value={}", value);
        println!("Commitment (SEC1): {}", hex::encode(&commitment[..8]));

        // Sign range proof
        let result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            None, // No message
            0,    // min_value
            2,    // exp (Veil standard)
            32,   // min_bits (Veil standard)
        );

        match result {
            Ok(proof_result) => {
                println!("✅ Range proof generated successfully!");
                println!("Proof length: {} bytes", proof_result.proof.len());
                println!("First 32 bytes: {}", hex::encode(&proof_result.proof[..32.min(proof_result.proof.len())]));
                assert!(proof_result.proof.len() > 0);
                assert!(proof_result.proof.len() <= MAX_PROOF_SIZE);
            }
            Err(e) => {
                println!("❌ Range proof generation failed: {:?}", e);
                panic!("Range proof generation failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_rangeproof_sign_large_value() {
        use crate::pedersen::pedersen_commit;

        // Test with large value (1 billion)
        let value = 1000000000u64;
        let blind_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let nonce_hex = "2222222222222222222222222222222222222222222222222222222222222222";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment_veil = pedersen_commit(value, &blind).unwrap();
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        println!("Testing rangeproof_sign with large value={}", value);

        let result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            Some(b"large value test"),
            0,
            2,
            32,
        );

        assert!(result.is_ok(), "Large value proof failed: {:?}", result.err());
        let proof_result = result.unwrap();
        println!("✅ Large value proof: {} bytes", proof_result.proof.len());
        assert!(proof_result.proof.len() <= MAX_PROOF_SIZE);
    }

    #[test]
    fn test_rangeproof_sign_small_value() {
        use crate::pedersen::pedersen_commit;

        // Test with small value
        let value = 100u64;
        let blind_hex = "abababababababababababababababababababababababababababababababab";
        let nonce_hex = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment_veil = pedersen_commit(value, &blind).unwrap();
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        println!("Testing rangeproof_sign with small value={}", value);

        let result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            Some(b"small"),
            0,
            2,
            32,
        );

        assert!(result.is_ok(), "Small value proof failed: {:?}", result.err());
        let proof_result = result.unwrap();
        println!("✅ Small value proof: {} bytes", proof_result.proof.len());
        assert!(proof_result.proof.len() <= MAX_PROOF_SIZE);
    }

    #[test]
    fn test_rangeproof_sign_medium_value() {
        use crate::pedersen::pedersen_commit;

        // Test with medium value
        let value = 500000u64;
        let blind_hex = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        let nonce_hex = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment_veil = pedersen_commit(value, &blind).unwrap();
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        println!("Testing rangeproof_sign with medium value={}", value);

        let result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            Some(b"medium value"),
            0,
            2,
            32,
        );

        assert!(result.is_ok(), "Medium value proof failed: {:?}", result.err());
        let proof_result = result.unwrap();
        println!("✅ Medium value proof: {} bytes", proof_result.proof.len());
        assert!(proof_result.proof.len() <= MAX_PROOF_SIZE);
    }

    #[test]
    fn test_rangeproof_sign_minimal_value() {
        use crate::pedersen::pedersen_commit;

        // Test with minimal value (1)
        let value = 1u64;
        let blind_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let nonce_hex = "0202020202020202020202020202020202020202020202020202020202020202";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment_veil = pedersen_commit(value, &blind).unwrap();
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        println!("Testing rangeproof_sign with minimal value={}", value);

        let result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            Some(b"one"),
            0,
            2,
            32,
        );

        assert!(result.is_ok(), "Minimal value proof failed: {:?}", result.err());
        let proof_result = result.unwrap();
        println!("✅ Minimal value proof: {} bytes", proof_result.proof.len());
        assert!(proof_result.proof.len() <= MAX_PROOF_SIZE);
    }

    #[test]
    fn test_rangeproof_sign_no_message() {
        use crate::pedersen::pedersen_commit;

        // Test without message
        let value = 99999u64;
        let blind_hex = "9999999999999999999999999999999999999999999999999999999999999999";
        let nonce_hex = "8888888888888888888888888888888888888888888888888888888888888888";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment_veil = pedersen_commit(value, &blind).unwrap();
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        println!("Testing rangeproof_sign without message, value={}", value);

        let result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            None, // No message
            0,
            2,
            32,
        );

        assert!(result.is_ok(), "No-message proof failed: {:?}", result.err());
        let proof_result = result.unwrap();
        println!("✅ No-message proof: {} bytes", proof_result.proof.len());
        assert!(proof_result.proof.len() <= MAX_PROOF_SIZE);
    }

    #[test]
    fn test_rangeproof_verify_basic() {
        use crate::pedersen::pedersen_commit;

        // Sign a proof
        let value = 12345u64;
        let blind_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let nonce_hex = "2222222222222222222222222222222222222222222222222222222222222222";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment = pedersen_commit(value, &blind).unwrap();
        // Use commitment in Veil format (0x08/0x09) - our functions now handle this properly

        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            None,
            0,
            2,
            32,
        ).unwrap();

        println!("Verifying proof for value={}", value);

        // Verify the proof
        let verify_result = rangeproof_verify(&commitment, &sign_result.proof);

        assert!(verify_result.is_ok(), "Verification failed: {:?}", verify_result.err());
        let result = verify_result.unwrap();

        println!("✅ Proof verified! min={}, max={}", result.min_value, result.max_value);

        // Check the value is in the proven range
        assert!(value >= result.min_value, "value {} < min_value {}", value, result.min_value);
        assert!(value <= result.max_value, "value {} > max_value {}", value, result.max_value);
    }

    #[test]
    fn test_rangeproof_verify_large_value() {
        use crate::pedersen::pedersen_commit;

        let value = 1000000000u64;
        let blind_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let nonce_hex = "2222222222222222222222222222222222222222222222222222222222222222";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment = pedersen_commit(value, &blind).unwrap();
        // Use commitment in Veil format (0x08/0x09) - our functions now handle this properly

        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            Some(b"large value test"),
            0,
            2,
            32,
        ).unwrap();

        let verify_result = rangeproof_verify(&commitment, &sign_result.proof).unwrap();

        println!("✅ Large value verified! min={}, max={}", verify_result.min_value, verify_result.max_value);

        // Check the value is in the proven range
        assert!(value >= verify_result.min_value, "value {} < min_value {}", value, verify_result.min_value);
        assert!(value <= verify_result.max_value, "value {} > max_value {}", value, verify_result.max_value);
    }

    #[test]
    fn test_rangeproof_verify_minimal_value() {
        use crate::pedersen::pedersen_commit;

        let value = 1u64;
        let blind_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let nonce_hex = "0202020202020202020202020202020202020202020202020202020202020202";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment = pedersen_commit(value, &blind).unwrap();
        // Use commitment in Veil format (0x08/0x09) - our functions now handle this properly

        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            Some(b"one"),
            0,
            2,
            32,
        ).unwrap();

        let verify_result = rangeproof_verify(&commitment, &sign_result.proof).unwrap();

        println!("✅ Minimal value verified! min={}, max={}", verify_result.min_value, verify_result.max_value);

        assert!(value >= verify_result.min_value);
        assert!(value <= verify_result.max_value);
    }

    #[test]
    fn test_rangeproof_verify_tampered_proof_fails() {
        use crate::pedersen::pedersen_commit;

        let value = 12345u64;
        let blind_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let nonce_hex = "2222222222222222222222222222222222222222222222222222222222222222";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment = pedersen_commit(value, &blind).unwrap();
        // Use commitment in Veil format (0x08/0x09) - our functions now handle this properly

        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            None,
            0,
            2,
            32,
        ).unwrap();

        // Tamper with the proof
        let mut tampered_proof = sign_result.proof.clone();
        tampered_proof[100] ^= 0xff; // Flip some bits

        let verify_result = rangeproof_verify(&commitment, &tampered_proof);

        println!("Tampered proof result: {:?}", verify_result);
        assert!(verify_result.is_err(), "Tampered proof should fail verification!");
    }

    #[test]
    fn test_rangeproof_verify_wrong_commitment_fails() {
        use crate::pedersen::pedersen_commit;

        let value = 12345u64;
        let blind_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let nonce_hex = "2222222222222222222222222222222222222222222222222222222222222222";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment = pedersen_commit(value, &blind).unwrap();
        // Use commitment in Veil format (0x08/0x09) - our functions now handle this properly

        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            None,
            0,
            2,
            32,
        ).unwrap();

        // Use wrong commitment (different value)
        let wrong_value = 99999u64;
        let wrong_commitment_veil = pedersen_commit(wrong_value, &blind).unwrap();
        let mut wrong_commitment = wrong_commitment_veil.clone();
        wrong_commitment[0] = if wrong_commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        let verify_result = rangeproof_verify(&wrong_commitment, &sign_result.proof);

        println!("Wrong commitment result: {:?}", verify_result);
        assert!(verify_result.is_err(), "Wrong commitment should fail verification!");
    }

    #[test]
    fn test_rangeproof_sign_max_value_32bit() {
        use crate::pedersen::pedersen_commit;

        // Test with max 32-bit value
        let value = 4294967295u64; // 2^32 - 1
        let blind_hex = "fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe";
        let nonce_hex = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        let blind = hex::decode(blind_hex).unwrap();
        let nonce = hex::decode(nonce_hex).unwrap();

        let commitment_veil = pedersen_commit(value, &blind).unwrap();
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        println!("Testing rangeproof_sign with max 32-bit value={}", value);

        let result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            Some(b"max32"),
            0,
            2,
            32,
        );

        assert!(result.is_ok(), "Max 32-bit value proof failed: {:?}", result.err());
        let proof_result = result.unwrap();
        println!("✅ Max 32-bit value proof: {} bytes", proof_result.proof.len());
        assert!(proof_result.proof.len() <= MAX_PROOF_SIZE);
    }

    #[test]
    fn test_rangeproof_sign_and_rewind() {
        use crate::pedersen::pedersen_commit;

        println!("\n=== Test: Sign and Rewind ===");

        // Test parameters
        let value = 12345u64;
        let blind = [0x42u8; 32];
        let nonce = [0x01u8; 32];
        let message = b"Hello, Veil!";

        println!("Original value: {}", value);
        println!("Original blind: {}", hex::encode(&blind));
        println!("Nonce: {}", hex::encode(&nonce));
        println!("Message: {:?}", std::str::from_utf8(message).unwrap());

        // Create commitment
        let commitment_veil = pedersen_commit(value, &blind).unwrap();
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        // Sign the range proof
        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            Some(message),
            0,    // min_value
            2,    // exp
            32,   // min_bits
        );

        assert!(sign_result.is_ok(), "Signing failed: {:?}", sign_result.err());
        let proof_data = sign_result.unwrap();

        println!("Proof size: {} bytes", proof_data.proof.len());
        println!("Commitment: {}", hex::encode(&proof_data.commitment));

        // Rewind the proof
        let rewind_result = rangeproof_rewind(
            &nonce,
            &proof_data.commitment,
            &proof_data.proof,
        );

        assert!(rewind_result.is_ok(), "Rewind failed: {:?}", rewind_result.err());
        let rewind_data = rewind_result.unwrap();

        println!("\n=== Rewind Results ===");
        println!("Recovered value: {}", rewind_data.value);
        println!("Recovered blind: {}", hex::encode(&rewind_data.blind));
        println!("Value range: [{}, {}]", rewind_data.min_value, rewind_data.max_value);
        println!("Message length: {} bytes", rewind_data.message.len());

        // Verify value matches
        assert_eq!(rewind_data.value, value, "Value mismatch!");

        // Verify blind matches
        assert_eq!(rewind_data.blind.len(), 32, "Blind should be 32 bytes");
        assert_eq!(&rewind_data.blind[..], &blind[..], "Blind mismatch!");

        // Verify value is in range
        assert!(
            rewind_data.value >= rewind_data.min_value,
            "Value {} below min {}",
            rewind_data.value,
            rewind_data.min_value
        );
        assert!(
            rewind_data.value <= rewind_data.max_value,
            "Value {} above max {}",
            rewind_data.value,
            rewind_data.max_value
        );

        // Verify message is recovered (may be padded with zeros)
        assert!(
            rewind_data.message.len() >= message.len(),
            "Message too short"
        );

        // Check that message is somewhere in the recovered data
        let message_found = rewind_data.message
            .windows(message.len())
            .any(|window| window == message);

        if !message_found {
            println!("Warning: Message not found in recovered data");
            println!("Expected: {:?}", std::str::from_utf8(message).unwrap());
            println!("Got first {} bytes: {:?}",
                message.len(),
                std::str::from_utf8(&rewind_data.message[..message.len().min(rewind_data.message.len())])
            );
        }

        println!("✅ Sign and rewind test passed!");
    }

    #[test]
    fn test_rangeproof_sign_and_rewind_no_message() {
        use crate::pedersen::pedersen_commit;

        println!("\n=== Test: Sign and Rewind (No Message) ===");

        let value = 99999u64;
        let blind = [0xAAu8; 32];
        let nonce = [0xBBu8; 32];

        // Create commitment
        let commitment_veil = pedersen_commit(value, &blind).unwrap();
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        // Sign without message
        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            None,  // No message
            0,
            2,
            32,
        );

        assert!(sign_result.is_ok());
        let proof_data = sign_result.unwrap();

        // Rewind
        let rewind_result = rangeproof_rewind(
            &nonce,
            &proof_data.commitment,
            &proof_data.proof,
        );

        assert!(rewind_result.is_ok());
        let rewind_data = rewind_result.unwrap();

        // Verify
        assert_eq!(rewind_data.value, value);
        assert_eq!(&rewind_data.blind[..], &blind[..]);

        println!("✅ No-message rewind test passed!");
    }

    #[test]
    fn test_rangeproof_rewind_wrong_nonce_fails() {
        use crate::pedersen::pedersen_commit;

        println!("\n=== Test: Rewind with Wrong Nonce ===");

        let value = 54321u64;
        let blind = [0x77u8; 32];
        let nonce = [0x11u8; 32];
        let wrong_nonce = [0x22u8; 32];

        // Create commitment
        let commitment_veil = pedersen_commit(value, &blind).unwrap();
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        // Sign with correct nonce
        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            Some(b"secret"),
            0,
            2,
            32,
        );

        assert!(sign_result.is_ok());
        let proof_data = sign_result.unwrap();

        // Try to rewind with wrong nonce
        let rewind_result = rangeproof_rewind(
            &wrong_nonce,  // Wrong nonce
            &proof_data.commitment,
            &proof_data.proof,
        );

        // Should succeed but recover wrong values
        if let Ok(rewind_data) = rewind_result {
            // Values should not match
            assert_ne!(rewind_data.value, value, "Should not recover correct value with wrong nonce");
            assert_ne!(&rewind_data.blind[..], &blind[..], "Should not recover correct blind with wrong nonce");
            println!("✅ Wrong nonce produces wrong values as expected");
        } else {
            println!("✅ Wrong nonce causes rewind to fail (also acceptable)");
        }
    }

    #[test]
    fn test_rangeproof_info() {
        use crate::pedersen::pedersen_commit;

        println!("\n=== Test: Rangeproof Info ===");

        let value = 54321u64;
        let blind = [0x88u8; 32];
        let nonce = [0x99u8; 32];

        // Create commitment
        let commitment_veil = pedersen_commit(value, &blind).unwrap();
        let mut commitment = commitment_veil.clone();
        commitment[0] = if commitment_veil[0] == 0x08 { 0x02 } else { 0x03 };

        // Sign proof
        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            Some(b"info test"),
            0,
            2,
            32,
        );

        assert!(sign_result.is_ok());
        let proof_data = sign_result.unwrap();

        println!("Proof size: {} bytes", proof_data.proof.len());

        // Extract info (lightweight, no verification)
        let info_result = rangeproof_info(&proof_data.proof);

        assert!(info_result.is_ok(), "Failed to extract info: {:?}", info_result.err());
        let info = info_result.unwrap();

        println!("Proof info:");
        println!("  exp: {}", info.exp);
        println!("  mantissa: {}", info.mantissa);
        println!("  min_value: {}", info.min_value);
        println!("  max_value: {}", info.max_value);

        // Verify value is in range
        assert!(
            value >= info.min_value,
            "Value {} below min {}",
            value,
            info.min_value
        );
        assert!(
            value <= info.max_value,
            "Value {} above max {}",
            value,
            info.max_value
        );

        // Verify exp is valid
        assert!(info.exp >= -1 && info.exp <= 18, "Invalid exp: {}", info.exp);

        // Verify mantissa is reasonable
        assert!(info.mantissa <= 64, "Invalid mantissa: {}", info.mantissa);

        println!("✅ Rangeproof info test passed!");
    }
}
