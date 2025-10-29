//! ECDH_VEIL - Pure Rust Implementation
//!
//! Elliptic Curve Diffie-Hellman for generating shared secrets.
//! Veil uses this for stealth address derivation.
//!
//! ## Algorithm
//!
//! ```text
//! SharedSecret = SHA256(compressed_point)
//!
//! Where:
//!   compressed_point = privkey * pubkey (ECDH scalar multiplication)
//!   Format: [0x02 or 0x03][32 bytes x-coordinate]
//! ```
//!
//! ## Pure Rust Implementation
//!
//! This implementation uses k256 (pure Rust secp256k1) instead of C FFI.
//! It's fully compatible with WASM compilation.

use crate::{Result, VeilCryptoError};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    PublicKey as K256PublicKey, Scalar,
};
#[cfg(test)]
use k256::ProjectivePoint;
use sha2::{Digest, Sha256};

/// Perform ECDH_VEIL to generate a shared secret
///
/// # Arguments
///
/// * `pubkey_bytes` - The other party's public key (33 or 65 bytes)
/// * `privkey_bytes` - Our secret key (32 bytes)
///
/// # Returns
///
/// 32-byte shared secret (SHA256 of the ECDH point)
///
/// # Algorithm
///
/// 1. Parse public key and private key
/// 2. Compute ECDH: shared_point = privkey * pubkey
/// 3. Serialize shared_point in compressed format (33 bytes)
/// 4. Hash with SHA256: result = SHA256(compressed_point)
///
/// # Errors
///
/// Returns `VeilCryptoError::InvalidPublicKey` or `InvalidSecretKey` if inputs are invalid.
///
/// # Example
///
/// ```ignore
/// use veil_crypto::ecdh::ecdh_veil;
///
/// let pubkey = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
/// let privkey = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
///
/// let shared_secret = ecdh_veil(&pubkey, &privkey).unwrap();
/// assert_eq!(shared_secret.len(), 32);
/// ```
pub fn ecdh_veil(pubkey_bytes: &[u8], privkey_bytes: &[u8]) -> Result<Vec<u8>> {
    // Parse public key (can be compressed 33 bytes or uncompressed 65 bytes)
    let pubkey = K256PublicKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|_| VeilCryptoError::InvalidPublicKey)?;

    let pubkey_point = pubkey.to_projective();

    // Parse private key (32 bytes)
    if privkey_bytes.len() != 32 {
        return Err(VeilCryptoError::InvalidSecretKey);
    }

    let privkey_array: [u8; 32] = privkey_bytes
        .try_into()
        .map_err(|_| VeilCryptoError::InvalidSecretKey)?;

    let privkey = Scalar::from_repr(privkey_array.into())
        .into_option()
        .ok_or(VeilCryptoError::InvalidSecretKey)?;

    // Perform scalar multiplication: shared_point = privkey * pubkey
    let shared_point = pubkey_point * privkey;

    // Convert to affine coordinates and get compressed encoding
    let affine_point = shared_point.to_affine();
    let compressed = affine_point.to_encoded_point(true); // true = compressed format

    // Hash the compressed point with SHA256
    let hash = Sha256::digest(compressed.as_bytes());

    Ok(hash.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_basic() {
        // Generator point (G) compressed
        let pubkey =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        let result = ecdh_veil(&pubkey, &privkey);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_ecdh_deterministic() {
        // Same inputs should always give same output
        let pubkey =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        let result1 = ecdh_veil(&pubkey, &privkey).unwrap();
        let result2 = ecdh_veil(&pubkey, &privkey).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_ecdh_commutative() {
        // ECDH should be commutative: Alice->Bob == Bob->Alice
        let sk_alice =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let sk_bob =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();

        // Generate public keys
        let sk_alice_array: [u8; 32] = sk_alice.as_slice().try_into().unwrap();
        let sk_bob_array: [u8; 32] = sk_bob.as_slice().try_into().unwrap();

        let scalar_alice = Scalar::from_repr(sk_alice_array.into())
            .into_option()
            .unwrap();
        let scalar_bob = Scalar::from_repr(sk_bob_array.into())
            .into_option()
            .unwrap();
        let g = ProjectivePoint::GENERATOR;

        let pk_alice = (g * scalar_alice).to_affine().to_encoded_point(true);
        let pk_bob = (g * scalar_bob).to_affine().to_encoded_point(true);

        // Compute shared secrets
        let shared_ab = ecdh_veil(pk_bob.as_bytes(), &sk_alice).unwrap();
        let shared_ba = ecdh_veil(pk_alice.as_bytes(), &sk_bob).unwrap();

        // Should be identical
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn test_ecdh_invalid_pubkey() {
        let invalid_pubkey = vec![0u8; 33]; // All zeros is invalid
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        let result = ecdh_veil(&invalid_pubkey, &privkey);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdh_invalid_privkey() {
        let pubkey =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let invalid_privkey = vec![0u8; 31]; // Wrong length

        let result = ecdh_veil(&pubkey, &invalid_privkey);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdh_veil_vector_1() {
        // Test vector from Veil C implementation
        // Generator point with privkey=2
        let pubkey =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let expected =
            hex::decode("b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7")
                .unwrap();

        let result = ecdh_veil(&pubkey, &privkey).unwrap();
        assert_eq!(
            result, expected,
            "ECDH result doesn't match C implementation!\nExpected: {}\nGot:      {}",
            hex::encode(&expected),
            hex::encode(&result)
        );
    }

    #[test]
    fn test_ecdh_veil_vector_2_commutative() {
        // Test vector from Veil C implementation
        // 2*G with privkey=1 (should match vector 1 - tests commutativity)
        let pubkey =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap();
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let expected =
            hex::decode("b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7")
                .unwrap();

        let result = ecdh_veil(&pubkey, &privkey).unwrap();
        assert_eq!(
            result, expected,
            "ECDH commutativity test failed!\nExpected: {}\nGot:      {}",
            hex::encode(&expected),
            hex::encode(&result)
        );
    }
}
