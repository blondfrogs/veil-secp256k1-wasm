//! Utility Functions
//!
//! Helper functions for crypto operations

use sha2::{Digest, Sha256};
use sha3::Keccak256;
use k256::{
    elliptic_curve::{
        sec1::{ToEncodedPoint, FromEncodedPoint},
        PrimeField,
    },
    ProjectivePoint, Scalar, AffinePoint
};
use crate::{Result, VeilCryptoError};

// Helper macro for array references
macro_rules! array_ref {
    ($arr:expr, $offset:expr, $len:expr) => {{
        {
            #[inline]
            fn as_array<T>(slice: &[T]) -> &[T; $len] {
                unsafe { &*(slice.as_ptr() as *const [T; $len]) }
            }
            as_array(&$arr[$offset..$offset + $len])
        }
    }};
}

/// Hash data with SHA256
pub fn hash_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash data with Keccak256 (SHA3 variant)
pub fn hash_keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ============================================================================
// Elliptic Curve Operations
// ============================================================================

/// Derive a public key from a secret key
///
/// pubkey = secret * G (where G is the generator point)
pub fn derive_pubkey(secret: &[u8]) -> Result<Vec<u8>> {
    if secret.len() != 32 {
        return Err(VeilCryptoError::InvalidSecretKey);
    }

    // Parse the secret key
    let scalar = Scalar::from_repr((*array_ref![secret, 0, 32]).into())
        .into_option()
        .ok_or(VeilCryptoError::InvalidSecretKey)?;

    // Multiply generator by scalar
    let point = ProjectivePoint::GENERATOR * scalar;

    // Convert to compressed format
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true); // Compressed

    Ok(encoded.as_bytes().to_vec())
}

/// Add a scalar * G to a public key point
///
/// result = pubkey + (scalar * G)
///
/// This is used in stealth address destination key derivation
pub fn point_add_scalar(pubkey: &[u8], scalar: &[u8]) -> Result<Vec<u8>> {
    if pubkey.len() != 33 {
        return Err(VeilCryptoError::InvalidPublicKey);
    }
    if scalar.len() != 32 {
        return Err(VeilCryptoError::InvalidSecretKey);
    }

    // Parse the public key
    let point = AffinePoint::from_encoded_point(&k256::EncodedPoint::from_bytes(pubkey).map_err(|_| VeilCryptoError::InvalidPublicKey)?)
        .into_option()
        .ok_or(VeilCryptoError::InvalidPublicKey)?;

    // Parse the scalar
    let scalar_val = Scalar::from_repr((*array_ref![scalar, 0, 32]).into())
        .into_option()
        .ok_or(VeilCryptoError::InvalidSecretKey)?;

    // Compute scalar * G
    let scalar_point = ProjectivePoint::GENERATOR * scalar_val;

    // Add to the public key
    let result = ProjectivePoint::from(point) + scalar_point;

    // Convert to compressed format
    let affine = result.to_affine();
    let encoded = affine.to_encoded_point(true);

    Ok(encoded.as_bytes().to_vec())
}

/// Multiply a public key point by a scalar
///
/// result = scalar * pubkey
pub fn point_multiply(pubkey: &[u8], scalar: &[u8]) -> Result<Vec<u8>> {
    if pubkey.len() != 33 {
        return Err(VeilCryptoError::InvalidPublicKey);
    }
    if scalar.len() != 32 {
        return Err(VeilCryptoError::InvalidSecretKey);
    }

    // Parse the public key
    let point = AffinePoint::from_encoded_point(&k256::EncodedPoint::from_bytes(pubkey).map_err(|_| VeilCryptoError::InvalidPublicKey)?)
        .into_option()
        .ok_or(VeilCryptoError::InvalidPublicKey)?;

    // Parse the scalar
    let scalar_val = Scalar::from_repr((*array_ref![scalar, 0, 32]).into())
        .into_option()
        .ok_or(VeilCryptoError::InvalidSecretKey)?;

    // Multiply
    let result = ProjectivePoint::from(point) * scalar_val;

    // Convert to compressed format
    let affine = result.to_affine();
    let encoded = affine.to_encoded_point(true);

    Ok(encoded.as_bytes().to_vec())
}

/// Add two secret keys (mod curve order)
///
/// result = (a + b) mod n
pub fn private_add(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    if a.len() != 32 || b.len() != 32 {
        return Err(VeilCryptoError::InvalidSecretKey);
    }

    // Parse scalars
    let a_scalar = Scalar::from_repr((*array_ref![a, 0, 32]).into())
        .into_option()
        .ok_or(VeilCryptoError::InvalidSecretKey)?;
    let b_scalar = Scalar::from_repr((*array_ref![b, 0, 32]).into())
        .into_option()
        .ok_or(VeilCryptoError::InvalidSecretKey)?;

    // Add (mod n)
    let result = a_scalar + b_scalar;

    Ok(result.to_bytes().to_vec())
}

/// Hash-to-point function (placeholder)
///
/// # TODO
///
/// - Implement a proper hash-to-curve function
/// - Must match Veil's implementation exactly
/// - This is used in key image generation
pub fn hash_to_point(_data: &[u8]) -> Vec<u8> {
    // TODO: Implement based on Veil's algorithm
    // This is critical for key images
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_sha256() {
        let data = b"hello world";
        let hash = hash_sha256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_keccak256() {
        let data = b"hello world";
        let hash = hash_keccak256(data);
        assert_eq!(hash.len(), 32);
    }
}
