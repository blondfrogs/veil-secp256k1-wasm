//! Key Image Generation for RingCT - Pure Rust Implementation
//!
//! Key images are used in RingCT to prevent double-spending without revealing
//! which output is being spent. Each key image is unique to a specific output
//! and secret key combination.
//!
//! ## Algorithm (from Veil's C code - main_impl.h:194-224)
//!
//! The key image for a public key P and secret key x is computed as:
//! ```text
//! I = x * H(P)
//! ```
//! Where H(P) is a hash-to-point function that maps the public key to a point on the curve.
//!
//! ## Implementation
//!
//! 1. Hash public key to curve point using try-and-increment: H(pk)
//! 2. Parse secret key as scalar
//! 3. Multiply: KI = sk * H(pk)
//! 4. Serialize as compressed point (33 bytes)
//!
//! ## Pure Rust
//!
//! This implementation uses k256 (pure Rust secp256k1) instead of C FFI.
//! It's fully compatible with WASM compilation.

use crate::{Result, VeilCryptoError};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
};
use sha2::{Digest, Sha256};

/// Hash arbitrary data to a curve point using re-hashing method
///
/// This matches Veil's C implementation in main_impl.h:167-192
///
/// Algorithm (from C code):
/// 1. hash = SHA256(data)
/// 2. Try to use hash as x-coordinate (with even y only, not odd)
/// 3. If it works, return the point
/// 4. If it fails, hash = SHA256(hash) and go to step 2
/// 5. Repeat up to 128 times
///
/// Note: The C code only tries even y-coordinates (`rustsecp256k1_v0_4_1_ge_set_xo_var(ge, &x, 0)`)
///
/// # Arguments
///
/// * `data` - The data to hash (typically a public key)
///
/// # Returns
///
/// A curve point, or error if hash-to-curve fails after 128 attempts
pub(crate) fn hash_to_curve(data: &[u8]) -> Result<ProjectivePoint> {
    const SAFETY: usize = 128; // Match C code's safety limit

    // Initial hash of the data
    let mut hash = Sha256::digest(data);

    // Try up to SAFETY iterations
    for _ in 0..SAFETY {
        // Try to use hash as x-coordinate with even y (0x02 prefix)
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02; // Even y-coordinate (matches C code's ge_set_xo_var(..., 0))
        compressed[1..].copy_from_slice(&hash);

        // Try to decode as compressed point
        if let Ok(encoded) = EncodedPoint::from_bytes(&compressed) {
            if let Ok(point) = AffinePoint::try_from(&encoded) {
                // Validate it's a valid point (though try_from should ensure this)
                return Ok(point.into());
            }
        }

        // Failed - re-hash the hash itself (not the original data!)
        hash = Sha256::digest(&hash);
    }

    // All SAFETY attempts failed
    Err(VeilCryptoError::Other(
        format!("hash_to_curve failed: no valid point found after {} attempts", SAFETY),
    ))
}

/// Generate a key image from a public key and secret key
///
/// # Arguments
///
/// * `pk_bytes` - The public key (33 bytes compressed or 65 bytes uncompressed)
/// * `sk_bytes` - The secret key (32 bytes)
///
/// # Returns
///
/// The key image as a compressed public key (33 bytes)
///
/// # Errors
///
/// Returns `VeilCryptoError` if the keys are invalid or hash-to-curve fails
///
/// # Algorithm (from Veil's C code)
///
/// ```text
/// KI = sk * H(pk)
/// ```
///
/// Where:
/// - H(pk) is hash_to_curve(pk) - maps public key to curve point
/// - sk is the secret key as a scalar
/// - * is scalar multiplication
///
/// # Example
///
/// ```ignore
/// use veil_crypto::keyimage::get_keyimage;
///
/// let pk = hex::decode("02...").unwrap();
/// let sk = hex::decode("01020304...").unwrap();
///
/// let key_image = get_keyimage(&pk, &sk).unwrap();
/// assert_eq!(key_image.len(), 33);
/// ```
pub fn get_keyimage(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>> {
    // Step 1: Hash public key to curve point
    // This uses the try-and-increment method to find a valid curve point
    let hashed_point = hash_to_curve(pk_bytes)?;

    // Step 2: Parse secret key as scalar
    if sk_bytes.len() != 32 {
        return Err(VeilCryptoError::InvalidSecretKey);
    }

    let sk_array: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| VeilCryptoError::InvalidSecretKey)?;

    let scalar = Scalar::from_repr(sk_array.into())
        .into_option()
        .ok_or(VeilCryptoError::InvalidSecretKey)?;

    // Step 3: Multiply: KI = scalar * H(pk)
    let key_image = hashed_point * scalar;

    // Step 4: Serialize as compressed point (33 bytes)
    let compressed = key_image.to_affine().to_encoded_point(true);

    Ok(compressed.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_curve_basic() {
        // Should be able to hash any data to a curve point
        let data = b"test data";
        let result = hash_to_curve(data);
        assert!(result.is_ok());

        // Result should be a valid point (not identity)
        let point = result.unwrap();
        assert_ne!(point, ProjectivePoint::IDENTITY);
    }

    #[test]
    fn test_hash_to_curve_deterministic() {
        // Same input should always give same output
        let data = b"test data";
        let result1 = hash_to_curve(data).unwrap();
        let result2 = hash_to_curve(data).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hash_to_curve_different_inputs() {
        // Different inputs should give different outputs
        let data1 = b"test data 1";
        let data2 = b"test data 2";
        let result1 = hash_to_curve(data1).unwrap();
        let result2 = hash_to_curve(data2).unwrap();
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_keyimage_basic() {
        // Simple test with valid inputs
        let pk = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let sk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();

        let result = get_keyimage(&pk, &sk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 33);
    }

    #[test]
    fn test_keyimage_deterministic() {
        // Same inputs should always give same output
        let pk = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let sk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();

        let result1 = get_keyimage(&pk, &sk).unwrap();
        let result2 = get_keyimage(&pk, &sk).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_keyimage_invalid_sk_length() {
        let pk = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let sk = vec![0u8; 31]; // Wrong length

        let result = get_keyimage(&pk, &sk);
        assert!(result.is_err());
    }

    // Test vectors from Veil C implementation
    #[test]
    fn test_keyimage_vector_1() {
        // From keyimage_test_vectors.json - "Simple incrementing bytes"
        let pk = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
        let sk = hex::decode("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40").unwrap();
        let expected = hex::decode("02ad397571b22342ecbcf22e51f85998fb8bc5696393fead098a87bb9b5a7cfa08").unwrap();

        let result = get_keyimage(&pk, &sk).unwrap();
        assert_eq!(
            result, expected,
            "Key image doesn't match C implementation!\nExpected: {}\nGot:      {}",
            hex::encode(&expected),
            hex::encode(&result)
        );
    }

    #[test]
    fn test_keyimage_vector_2() {
        // From keyimage_test_vectors.json - "Valid pubkey format with 0x02 prefix"
        let pk = hex::decode("0284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0").unwrap();
        let sk = hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
        let expected = hex::decode("038da64d9766497e356dc36a06c07b30e83170eb0430527fc7018445413db8ac6c").unwrap();

        let result = get_keyimage(&pk, &sk).unwrap();
        assert_eq!(
            result, expected,
            "Key image vector 2 doesn't match!\nExpected: {}\nGot:      {}",
            hex::encode(&expected),
            hex::encode(&result)
        );
    }

    #[test]
    fn test_keyimage_vector_3() {
        // From keyimage_test_vectors.json - "Valid pubkey format with 0x03 prefix"
        let pk = hex::decode("03020406080a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e40").unwrap();
        let sk = hex::decode("05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324").unwrap();
        let expected = hex::decode("02028e081e9a9596367d2044260c61da4f4cbd44ca39ed7a2c93d29a310c08d906").unwrap();

        let result = get_keyimage(&pk, &sk).unwrap();
        assert_eq!(
            result, expected,
            "Key image vector 3 doesn't match!\nExpected: {}\nGot:      {}",
            hex::encode(&expected),
            hex::encode(&result)
        );
    }
}
