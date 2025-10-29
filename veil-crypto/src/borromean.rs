//! Borromean Ring Signatures
//!
//! Borromean ring signatures are a ring signature construction that allows
//! proving knowledge of a secret key for one pubkey in each of multiple rings.
//!
//! This is used by Veil's range proofs to prove a committed value is in range
//! without revealing the value.
//!
//! ## Algorithm
//!
//! From the paper: "Borromean Ring Signatures" by Gregory Maxwell and Andrew Poelstra
//! https://github.com/Blockstream/borromean_paper
//!
//! Borromean signatures verify `nrings` concurrent ring signatures all sharing
//! a challenge value:
//!
//! ```text
//! Verification equation:
//! m = H(P_{0..}||message)
//! For each ring i:
//!   en = to_scalar(H(e0||m||i||0))
//!   For each pubkey j:
//!     r = s_i_j * G + en * P_i_j
//!     e = H(r||m||i||j)
//!     en = to_scalar(e)
//!   r_i = r
//! return e_0 == H(r_{0..i}||m)
//! ```

use crate::{Result, VeilCryptoError};
use k256::{
    AffinePoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        group::prime::PrimeCurveAffine,
        ops::MulByGenerator,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Group, PrimeField,
    },
};
use sha2::{Sha256, Digest};

/// Borromean hash function
///
/// Computes: H(e || m || ring_idx || element_idx)
///
/// This is the core hash function used in Borromean ring signatures.
///
/// # Arguments
///
/// * `e` - Previous hash value (32 bytes)
/// * `m` - Message being signed
/// * `ring_idx` - Index of the current ring
/// * `element_idx` - Index of the element within the ring
///
/// # Returns
///
/// 32-byte hash
///
/// # Algorithm
///
/// From C code (borromean_impl.h:28-42):
/// ```c
/// void borromean_hash(unsigned char *hash, const unsigned char *m, size_t mlen,
///                    const unsigned char *e, size_t elen,
///                    size_t ridx, size_t eidx) {
///     uint32_t ring = BE32((uint32_t)ridx);
///     uint32_t epos = BE32((uint32_t)eidx);
///     sha256_initialize(&sha256_en);
///     sha256_write(&sha256_en, e, elen);
///     sha256_write(&sha256_en, m, mlen);
///     sha256_write(&sha256_en, (unsigned char *)&ring, 4);
///     sha256_write(&sha256_en, (unsigned char *)&epos, 4);
///     sha256_finalize(&sha256_en, hash);
/// }
/// ```
pub fn borromean_hash(
    e: &[u8],
    message: &[u8],
    ring_idx: usize,
    element_idx: usize,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Hash the previous value (e)
    hasher.update(e);

    // Hash the message
    hasher.update(message);

    // Hash ring index as big-endian u32
    hasher.update((ring_idx as u32).to_be_bytes());

    // Hash element index as big-endian u32
    hasher.update((element_idx as u32).to_be_bytes());

    let result = hasher.finalize();
    result.into()
}

/// Verify a Borromean ring signature
///
/// Verifies `nrings` concurrent ring signatures all sharing a challenge value.
///
/// # Arguments
///
/// * `e0` - Initial challenge value (32 bytes)
/// * `s` - Array of signature scalars (32 bytes each)
/// * `pubs` - Public keys for all rings (33 bytes each, compressed)
/// * `rsizes` - Size of each ring
/// * `message` - Message that was signed
///
/// # Returns
///
/// `Ok(true)` if signature is valid, `Ok(false)` if invalid, `Err` on parse errors
///
/// # Algorithm
///
/// From C code (borromean_impl.h:58-119):
///
/// ```text
/// count = 0
/// sha256_e0 = new hasher
///
/// for each ring i:
///   en = to_scalar(H(e0 || m || i || 0))
///
///   for each pubkey j in ring:
///     // Verify s and en are non-zero and pub is valid
///     if s[count] == 0 or en == 0 or pubs[count] is infinity:
///       return false
///
///     // Compute: r = s[count] * G + en * pubs[count]
///     r = ecmult(pubs[count], en, s[count])
///     if r is infinity:
///       return false
///
///     // Serialize r as compressed point
///     tmp = serialize_compressed(r)
///
///     if j != last in ring:
///       // Hash for next iteration
///       en = to_scalar(H(tmp || m || i || j+1))
///     else:
///       // Last element - add to final hash
///       sha256_e0.write(tmp)
///
///     count++
///
/// sha256_e0.write(m)
/// final_hash = sha256_e0.finalize()
/// return e0 == final_hash
/// ```
pub fn borromean_verify(
    e0: &[u8; 32],
    s: &[[u8; 32]],
    pubs: &[[u8; 33]],
    rsizes: &[usize],
    message: &[u8],
) -> Result<bool> {
    // Validate inputs
    let nrings = rsizes.len();
    if nrings == 0 {
        return Err(VeilCryptoError::Other("No rings provided".into()));
    }

    let total_pubs: usize = rsizes.iter().sum();
    if s.len() != total_pubs || pubs.len() != total_pubs {
        return Err(VeilCryptoError::Other(
            format!("Signature length mismatch: s={}, pubs={}, expected={}",
                    s.len(), pubs.len(), total_pubs)
        ));
    }

    let mut count = 0;
    let mut sha256_e0 = Sha256::new();

    // Process each ring
    for (i, &ring_size) in rsizes.iter().enumerate() {
        // Initial challenge for this ring: en = H(e0 || m || i || 0)
        let hash = borromean_hash(e0, message, i, 0);
        let mut en = Scalar::from_repr(hash.into())
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid scalar from hash".into()))?;

        // Process each pubkey in the ring
        for j in 0..ring_size {
            // Parse signature scalar s[count]
            let s_scalar = Scalar::from_repr(s[count].into())
                .into_option()
                .ok_or_else(|| VeilCryptoError::InvalidSignature)?;

            // Check for zero scalar
            if s_scalar.is_zero().into() || en.is_zero().into() {
                return Ok(false);
            }

            // Parse public key
            let pub_point = AffinePoint::from_encoded_point(
                &k256::EncodedPoint::from_bytes(&pubs[count])
                    .map_err(|_| VeilCryptoError::InvalidPublicKey)?
            )
            .into_option()
            .ok_or(VeilCryptoError::InvalidPublicKey)?;

            // Check for point at infinity
            if bool::from(pub_point.is_identity()) {
                return Ok(false);
            }

            // Compute: r = s[count] * G + en * pubs[count]
            // This is the core verification equation
            let s_times_g = ProjectivePoint::mul_by_generator(&s_scalar);
            let en_times_pub = ProjectivePoint::from(pub_point) * en;
            let r = s_times_g + en_times_pub;

            // Check result is not infinity
            if bool::from(r.is_identity()) {
                return Ok(false);
            }

            // Serialize r as compressed point
            let r_affine = r.to_affine();
            let r_compressed = r_affine.to_encoded_point(true);
            let r_bytes = r_compressed.as_bytes();

            if j != ring_size - 1 {
                // Not the last element - compute next challenge
                let next_hash = borromean_hash(r_bytes, message, i, j + 1);
                en = Scalar::from_repr(next_hash.into())
                    .into_option()
                    .ok_or_else(|| VeilCryptoError::Other("Invalid scalar from hash".into()))?;
            } else {
                // Last element in ring - add to final hash
                sha256_e0.update(r_bytes);
            }

            count += 1;
        }
    }

    // Finalize: hash all the final r values with the message
    sha256_e0.update(message);
    let final_hash: [u8; 32] = sha256_e0.finalize().into();

    // Verify e0 matches the final hash
    Ok(final_hash == *e0)
}

/// Sign a Borromean ring signature
///
/// Creates `nrings` concurrent ring signatures proving knowledge of one secret key
/// in each ring, without revealing which one.
///
/// # Arguments
///
/// * `pubs` - Public keys for all rings (33 bytes each, compressed)
/// * `k` - Random nonces, one per ring (32 bytes each) - must be cryptographically random!
/// * `sec` - Secret keys, one per ring (32 bytes each)
/// * `rsizes` - Size of each ring
/// * `secidx` - Index of the real key in each ring
/// * `message` - Message to sign
///
/// # Returns
///
/// `Ok((e0, s))` where:
/// - `e0` is the initial challenge (32 bytes)
/// - `s` is the array of signature scalars (32 bytes each, one per pubkey)
///
/// # Algorithm
///
/// From C code (borromean_impl.h:121-223):
///
/// The algorithm works in two phases:
///
/// **Phase 1: Forge signatures AFTER the secret index**
/// ```text
/// for each ring i:
///   r = k[i] * G  (nonce commitment)
///
///   for j from (secidx[i] + 1) to end of ring:
///     // Create forgery with random s[count+j]
///     tmp = H(tmp || m || i || j)
///     en = to_scalar(tmp)
///     r = pubs[count+j] * en + s[count+j] * G
///
///   sha256_e0.write(last_r)
///
/// e0 = H(all_last_r || m)
/// ```
///
/// **Phase 2: Forge signatures BEFORE secret index, compute real signature**
/// ```text
/// for each ring i:
///   en = to_scalar(H(e0 || m || i || 0))
///
///   for j from 0 to (secidx[i] - 1):
///     // Create forgery
///     r = pubs[count+j] * en + s[count+j] * G
///     tmp = H(r || m || i || j+1)
///     en = to_scalar(tmp)
///
///   // Compute real signature at position secidx[i]
///   s[count + secidx[i]] = k[i] - en * sec[i]
/// ```
pub fn borromean_sign(
    pubs: &[[u8; 33]],
    k: &[[u8; 32]],
    sec: &[[u8; 32]],
    s_random: &[[u8; 32]], // Random values for forgery positions
    rsizes: &[usize],
    secidx: &[usize],
    message: &[u8],
) -> Result<([u8; 32], Vec<[u8; 32]>)> {
    let nrings = rsizes.len();

    // Validate inputs
    if nrings == 0 {
        return Err(VeilCryptoError::Other("No rings provided".into()));
    }
    if k.len() != nrings || sec.len() != nrings || secidx.len() != nrings {
        return Err(VeilCryptoError::Other("Invalid input lengths".into()));
    }

    let total_pubs: usize = rsizes.iter().sum();
    if pubs.len() != total_pubs || s_random.len() != total_pubs {
        return Err(VeilCryptoError::Other(
            format!("Pubkey/signature length mismatch: pubs={}, s_random={}, expected={}",
                    pubs.len(), s_random.len(), total_pubs)
        ));
    }

    // Verify secret indices are valid
    for (i, &idx) in secidx.iter().enumerate() {
        if idx >= rsizes[i] {
            return Err(VeilCryptoError::Other(
                format!("Invalid secret index {} for ring {} of size {}", idx, i, rsizes[i])
            ));
        }
    }

    // Initialize signature array with random values
    let mut s: Vec<Scalar> = Vec::with_capacity(total_pubs);
    for s_rand in s_random {
        let scalar = Scalar::from_repr((*s_rand).into())
            .into_option()
            .ok_or(VeilCryptoError::InvalidSecretKey)?;
        s.push(scalar);
    }

    // Parse nonces
    let mut k_scalars = Vec::with_capacity(nrings);
    for k_bytes in k {
        let scalar = Scalar::from_repr((*k_bytes).into())
            .into_option()
            .ok_or(VeilCryptoError::InvalidSecretKey)?;
        k_scalars.push(scalar);
    }

    // Parse secrets
    let mut sec_scalars = Vec::with_capacity(nrings);
    for sec_bytes in sec {
        let scalar = Scalar::from_repr((*sec_bytes).into())
            .into_option()
            .ok_or(VeilCryptoError::InvalidSecretKey)?;
        sec_scalars.push(scalar);
    }

    // PHASE 1: Generate forgeries AFTER the secret index, compute e0
    let mut sha256_e0 = Sha256::new();
    let mut count = 0;

    for (i, &ring_size) in rsizes.iter().enumerate() {
        // Compute r = k[i] * G
        let r_point = ProjectivePoint::mul_by_generator(&k_scalars[i]);
        if bool::from(r_point.is_identity()) {
            return Err(VeilCryptoError::Other("Nonce generated point at infinity".into()));
        }

        let r_affine = r_point.to_affine();
        let mut tmp = r_affine.to_encoded_point(true);

        // Forge signatures AFTER the secret index
        for j in (secidx[i] + 1)..ring_size {
            // Hash: tmp = H(tmp || m || i || j)
            let hash = borromean_hash(tmp.as_bytes(), message, i, j);
            let en = Scalar::from_repr(hash.into())
                .into_option()
                .ok_or_else(|| VeilCryptoError::Other("Invalid scalar from hash".into()))?;

            if bool::from(en.is_zero()) {
                return Err(VeilCryptoError::Other("Zero challenge in signing".into()));
            }

            // Parse pubkey
            let pub_point = AffinePoint::from_encoded_point(
                &k256::EncodedPoint::from_bytes(&pubs[count + j])
                    .map_err(|_| VeilCryptoError::InvalidPublicKey)?
            )
            .into_option()
            .ok_or(VeilCryptoError::InvalidPublicKey)?;

            // Compute forgery: r = pubs[count+j] * en + s[count+j] * G
            let en_times_pub = ProjectivePoint::from(pub_point) * en;
            let s_times_g = ProjectivePoint::mul_by_generator(&s[count + j]);
            let r = en_times_pub + s_times_g;

            if bool::from(r.is_identity()) {
                return Err(VeilCryptoError::Other("Forgery generated point at infinity".into()));
            }

            tmp = r.to_affine().to_encoded_point(true);
        }

        // Add final r to the hash
        sha256_e0.update(tmp.as_bytes());
        count += ring_size;
    }

    // Finalize e0
    sha256_e0.update(message);
    let e0: [u8; 32] = sha256_e0.finalize().into();

    // PHASE 2: Generate forgeries BEFORE secret index, compute real signature
    count = 0;
    for (i, &ring_size) in rsizes.iter().enumerate() {
        // Initial challenge for this ring
        let hash = borromean_hash(&e0, message, i, 0);
        let mut en = Scalar::from_repr(hash.into())
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid scalar from hash".into()))?;

        if bool::from(en.is_zero()) {
            return Err(VeilCryptoError::Other("Zero challenge in phase 2".into()));
        }

        // Forge signatures BEFORE the secret index
        for j in 0..secidx[i] {
            // Parse pubkey
            let pub_point = AffinePoint::from_encoded_point(
                &k256::EncodedPoint::from_bytes(&pubs[count + j])
                    .map_err(|_| VeilCryptoError::InvalidPublicKey)?
            )
            .into_option()
            .ok_or(VeilCryptoError::InvalidPublicKey)?;

            // Compute forgery: r = pubs[count+j] * en + s[count+j] * G
            let en_times_pub = ProjectivePoint::from(pub_point) * en;
            let s_times_g = ProjectivePoint::mul_by_generator(&s[count + j]);
            let r = en_times_pub + s_times_g;

            if bool::from(r.is_identity()) {
                return Err(VeilCryptoError::Other("Forgery generated point at infinity".into()));
            }

            // Hash for next iteration
            let r_compressed = r.to_affine().to_encoded_point(true);
            let next_hash = borromean_hash(r_compressed.as_bytes(), message, i, j + 1);
            en = Scalar::from_repr(next_hash.into())
                .into_option()
                .ok_or_else(|| VeilCryptoError::Other("Invalid scalar from hash".into()))?;

            if bool::from(en.is_zero()) {
                return Err(VeilCryptoError::Other("Zero challenge in forgery loop".into()));
            }
        }

        // Now en is the challenge at position secidx[i]
        // Compute real signature: s = k - en * sec
        let en_times_sec = en * sec_scalars[i];
        let real_sig = k_scalars[i] - en_times_sec;

        if bool::from(real_sig.is_zero()) {
            return Err(VeilCryptoError::Other("Real signature is zero - invalid nonce".into()));
        }

        s[count + secidx[i]] = real_sig;
        count += ring_size;
    }

    // Convert scalars to bytes
    let s_bytes: Vec<[u8; 32]> = s.iter()
        .map(|scalar| {
            let bytes = scalar.to_bytes();
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            array
        })
        .collect();

    Ok((e0, s_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_borromean_hash_basic() {
        let e = [0u8; 32];
        let message = b"test message";
        let hash = borromean_hash(&e, message, 0, 0);

        // Hash should be deterministic
        let hash2 = borromean_hash(&e, message, 0, 0);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_borromean_hash_different_indices() {
        let e = [0u8; 32];
        let message = b"test";

        let hash1 = borromean_hash(&e, message, 0, 0);
        let hash2 = borromean_hash(&e, message, 0, 1); // Different element_idx
        let hash3 = borromean_hash(&e, message, 1, 0); // Different ring_idx

        // All should be different
        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn test_borromean_hash_matches_expected_format() {
        // Test that our hash function produces consistent output
        let e = [0x42; 32];
        let message = b"hello world";
        let hash = borromean_hash(&e, message, 5, 10);

        // Hash should be 32 bytes
        assert_eq!(hash.len(), 32);

        // Should not be all zeros
        assert_ne!(hash, [0u8; 32]);
    }

    // ========== borromean_verify tests ==========

    #[test]
    fn test_borromean_verify_input_validation() {
        let e0 = [0u8; 32];
        let s = vec![];
        let pubs = vec![];
        let rsizes = vec![];
        let message = b"test";

        // Empty rings should error
        let result = borromean_verify(&e0, &s, &pubs, &rsizes, message);
        assert!(result.is_err());
    }

    #[test]
    fn test_borromean_verify_length_mismatch() {
        let e0 = [0u8; 32];
        let s = vec![[1u8; 32]]; // 1 signature
        let pubs = vec![[2u8; 33], [3u8; 33]]; // 2 pubkeys - mismatch!
        let rsizes = vec![2]; // Expecting 2 elements
        let message = b"test";

        // Length mismatch should error
        let result = borromean_verify(&e0, &s, &pubs, &rsizes, message);
        assert!(result.is_err());
    }

    #[test]
    fn test_borromean_verify_zero_scalar_rejection() {
        use k256::elliptic_curve::ops::MulByGenerator;

        // Create a valid pubkey
        let scalar = Scalar::from(5u64);
        let point = ProjectivePoint::mul_by_generator(&scalar);
        let pub_bytes = point.to_affine().to_encoded_point(true);
        let mut pub_array = [0u8; 33];
        pub_array.copy_from_slice(pub_bytes.as_bytes());

        let e0 = [0u8; 32];
        let s = vec![[0u8; 32]]; // Zero scalar - should be rejected
        let pubs = vec![pub_array];
        let rsizes = vec![1];
        let message = b"test";

        // Zero scalar should cause verification to return false
        let result = borromean_verify(&e0, &s, &pubs, &rsizes, message);
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_borromean_verify_invalid_pubkey() {
        let e0 = [0u8; 32];
        let s = vec![[1u8; 32]];
        let invalid_pub = [0xFFu8; 33]; // Invalid point
        let pubs = vec![invalid_pub];
        let rsizes = vec![1];
        let message = b"test";

        // Invalid pubkey should error
        let result = borromean_verify(&e0, &s, &pubs, &rsizes, message);
        assert!(result.is_err());
    }

    // ========== borromean_sign tests ==========

    #[test]
    fn test_borromean_sign_single_ring_roundtrip() {
        use k256::elliptic_curve::ops::MulByGenerator;

        // Create a ring of 3 pubkeys, we know the secret for index 1
        let secret = Scalar::from(12345u64);
        let pubkey = ProjectivePoint::mul_by_generator(&secret);

        // Other pubkeys (we don't know their secrets)
        let other1 = ProjectivePoint::mul_by_generator(&Scalar::from(11111u64));
        let other2 = ProjectivePoint::mul_by_generator(&Scalar::from(22222u64));

        // Convert to compressed bytes
        let mut pubs = Vec::new();
        for point in [other1, pubkey, other2] {
            let bytes = point.to_affine().to_encoded_point(true);
            let mut array = [0u8; 33];
            array.copy_from_slice(bytes.as_bytes());
            pubs.push(array);
        }

        // Signing parameters
        let nonce = Scalar::from(99999u64);
        let nonce_bytes = nonce.to_bytes();
        let mut nonce_array = [0u8; 32];
        nonce_array.copy_from_slice(&nonce_bytes);

        let secret_bytes = secret.to_bytes();
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&secret_bytes);

        // Random values for forgery positions (indices 0 and 2)
        let s_random = vec![
            [0x11u8; 32], // Random for position 0
            [0x00u8; 32], // Will be replaced with real sig at position 1
            [0x22u8; 32], // Random for position 2
        ];

        let message = b"test message";
        let rsizes = vec![3];
        let secidx = vec![1]; // We know the secret at index 1

        // Sign
        let (e0, s) = borromean_sign(
            &pubs,
            &[nonce_array],
            &[secret_array],
            &s_random,
            &rsizes,
            &secidx,
            message,
        ).unwrap();

        // Verify
        let verify_result = borromean_verify(&e0, &s, &pubs, &rsizes, message).unwrap();
        assert!(verify_result, "Signature should verify successfully");
    }

    #[test]
    fn test_borromean_sign_multiple_rings_roundtrip() {
        use k256::elliptic_curve::ops::MulByGenerator;

        // Ring 1: 2 pubkeys, secret at index 0
        let secret1 = Scalar::from(11111u64);
        let pub1_0 = ProjectivePoint::mul_by_generator(&secret1);
        let pub1_1 = ProjectivePoint::mul_by_generator(&Scalar::from(11112u64));

        // Ring 2: 3 pubkeys, secret at index 2
        let secret2 = Scalar::from(22222u64);
        let pub2_0 = ProjectivePoint::mul_by_generator(&Scalar::from(22220u64));
        let pub2_1 = ProjectivePoint::mul_by_generator(&Scalar::from(22221u64));
        let pub2_2 = ProjectivePoint::mul_by_generator(&secret2);

        // Convert to bytes
        let mut pubs = Vec::new();
        for point in [pub1_0, pub1_1, pub2_0, pub2_1, pub2_2] {
            let bytes = point.to_affine().to_encoded_point(true);
            let mut array = [0u8; 33];
            array.copy_from_slice(bytes.as_bytes());
            pubs.push(array);
        }

        // Nonces
        let nonce1_bytes = Scalar::from(99991u64).to_bytes();
        let mut nonce1 = [0u8; 32];
        nonce1.copy_from_slice(&nonce1_bytes);

        let nonce2_bytes = Scalar::from(99992u64).to_bytes();
        let mut nonce2 = [0u8; 32];
        nonce2.copy_from_slice(&nonce2_bytes);

        // Secrets
        let secret1_bytes = secret1.to_bytes();
        let mut secret1_array = [0u8; 32];
        secret1_array.copy_from_slice(&secret1_bytes);

        let secret2_bytes = secret2.to_bytes();
        let mut secret2_array = [0u8; 32];
        secret2_array.copy_from_slice(&secret2_bytes);

        // Random s values for forgeries
        let s_random = vec![
            [0x00u8; 32], // Real sig at ring1[0]
            [0x11u8; 32], // Forgery at ring1[1]
            [0x20u8; 32], // Forgery at ring2[0]
            [0x21u8; 32], // Forgery at ring2[1]
            [0x00u8; 32], // Real sig at ring2[2]
        ];

        let message = b"multi-ring test";
        let rsizes = vec![2, 3];
        let secidx = vec![0, 2]; // Secrets at ring1[0] and ring2[2]

        // Sign
        let (e0, s) = borromean_sign(
            &pubs,
            &[nonce1, nonce2],
            &[secret1_array, secret2_array],
            &s_random,
            &rsizes,
            &secidx,
            message,
        ).unwrap();

        // Verify
        let verify_result = borromean_verify(&e0, &s, &pubs, &rsizes, message).unwrap();
        assert!(verify_result, "Multi-ring signature should verify");
    }

    #[test]
    fn test_borromean_sign_invalid_secret_index() {
        use k256::elliptic_curve::ops::MulByGenerator;

        let pub1 = ProjectivePoint::mul_by_generator(&Scalar::from(1u64));
        let mut pub_array = [0u8; 33];
        pub_array.copy_from_slice(pub1.to_affine().to_encoded_point(true).as_bytes());

        let pubs = vec![pub_array];
        let nonce = [1u8; 32];
        let secret = [2u8; 32];
        let s_random = vec![[3u8; 32]];
        let rsizes = vec![1];
        let secidx = vec![5]; // Invalid! Out of bounds
        let message = b"test";

        let result = borromean_sign(&pubs, &[nonce], &[secret], &s_random, &rsizes, &secidx, message);
        assert!(result.is_err());
    }

    #[test]
    fn test_borromean_sign_different_messages_different_signatures() {
        use k256::elliptic_curve::ops::MulByGenerator;

        // Same setup
        let secret = Scalar::from(12345u64);
        let pubkey = ProjectivePoint::mul_by_generator(&secret);
        let mut pub_array = [0u8; 33];
        pub_array.copy_from_slice(pubkey.to_affine().to_encoded_point(true).as_bytes());

        let pubs = vec![pub_array];
        let nonce = Scalar::from(99999u64).to_bytes();
        let mut nonce_array = [0u8; 32];
        nonce_array.copy_from_slice(&nonce);

        let secret_bytes = secret.to_bytes();
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&secret_bytes);

        let s_random = vec![[0u8; 32]];
        let rsizes = vec![1];
        let secidx = vec![0];

        // Sign two different messages
        let (e0_1, s_1) = borromean_sign(
            &pubs, &[nonce_array], &[secret_array], &s_random, &rsizes, &secidx, b"message1"
        ).unwrap();

        let (e0_2, s_2) = borromean_sign(
            &pubs, &[nonce_array], &[secret_array], &s_random, &rsizes, &secidx, b"message2"
        ).unwrap();

        // Signatures should be different
        assert_ne!(e0_1, e0_2);
        assert_ne!(s_1[0], s_2[0]);
    }
}
