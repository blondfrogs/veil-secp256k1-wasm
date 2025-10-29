//! MLSAG - Multilayered Linkable Spontaneous Anonymous Group Signatures - Pure Rust
//!
//! MLSAG signatures are the core of RingCT, providing ring signatures with
//! multiple inputs and linkability via key images.
//!
//! This is a pure Rust implementation using k256, compatible with WASM.

use crate::{
    rangeproof::HmacDrbg,
    keyimage::hash_to_curve,
    Result, VeilCryptoError,
};
use k256::{
    elliptic_curve::{
        group::Group,
        ops::MulByGenerator,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    AffinePoint, EncodedPoint, FieldElement, ProjectivePoint, Scalar,
};
use sha2::{Digest, Sha256};

/// Maximum rows in MLSAG (arbitrary limit from C code)
const MLSAG_MAX_ROWS: usize = 33;

/// Result type for prepare_mlsag
#[derive(Debug, Clone)]
pub struct PrepareMlsagResult {
    /// Updated matrix M (public keys + commitment row)
    pub m: Vec<u8>,
    /// Computed blind sum for commitment row
    pub sk: Vec<u8>,
}

/// Result type for generate_mlsag
#[derive(Debug, Clone)]
pub struct GenerateMlsagResult {
    /// Key images (one per input)
    pub key_images: Vec<u8>,
    /// First signature component (c0)
    pub pc: Vec<u8>,
    /// Second signature component (ss values)
    pub ps: Vec<u8>,
}

// ============================================================================
// Helper Functions (from C code main_impl.h)
// ============================================================================

/// Load a Pedersen commitment from custom format (0x08/0x09 prefix)
///
/// Matches C code: pedersen_commitment_load() in main_impl.h:10-17
///
/// The C code:
/// 1. Extracts x-coordinate
/// 2. Calls secp256k1_ge_set_xquad to get canonical y (the quadratic residue)
/// 3. If bit 0 is set, negates the point
///
/// The relationship between QR and parity is point-dependent, so we must:
/// 1. Decompress with both parities (0x02 and 0x03)
/// 2. Check which y is the QR (canonical)
/// 3. Use QR if bit 0 = 0, use non-QR if bit 0 = 1
pub fn pedersen_commitment_load(commit: &[u8]) -> Result<ProjectivePoint> {
    if commit.len() != 33 {
        return Err(VeilCryptoError::Other("Commitment must be 33 bytes".into()));
    }

    // Match C code exactly:
    // 1. secp256k1_fe_set_b32(&fe, &commit[1]) - load x coordinate
    // 2. secp256k1_ge_set_xquad(ge, &fe) - compute sqrt(x³+7) to get canonical y (QR)
    // 3. if (commit[0] & 1) { secp256k1_ge_neg(ge, ge) } - negate if bit is set

    // Load x coordinate
    let x_bytes: [u8; 32] = commit[1..33]
        .try_into()
        .map_err(|_| VeilCryptoError::Other("Invalid x-coordinate slice".into()))?;
    let x = FieldElement::from_bytes(&x_bytes.into())
        .into_option()
        .ok_or_else(|| VeilCryptoError::Other("Invalid x-coordinate field element".into()))?;

    // Compute y² = x³ + 7
    let x_cubed = x * x * x;
    let b = FieldElement::from(7u64);
    let y_squared = x_cubed + b;

    // Compute sqrt(y²) - this gives us the canonical y (the QR)
    // This matches secp256k1_ge_set_xquad which computes a^((p+1)/4) mod p
    let y_canonical = y_squared.sqrt()
        .into_option()
        .ok_or_else(|| VeilCryptoError::Other("Point not on curve".into()))?;

    // Convert to bytes to create the point
    let y_bytes = y_canonical.to_bytes();

    // Create the point with canonical y
    let mut point_bytes = [0u8; 65];
    point_bytes[0] = 0x04; // Uncompressed format
    point_bytes[1..33].copy_from_slice(&x_bytes);
    point_bytes[33..65].copy_from_slice(&y_bytes);

    let encoded = EncodedPoint::from_bytes(&point_bytes)
        .map_err(|_| VeilCryptoError::Other("Invalid point encoding".into()))?;
    let point = AffinePoint::from_encoded_point(&encoded)
        .into_option()
        .ok_or_else(|| VeilCryptoError::Other("Invalid point".into()))?;

    let mut result: ProjectivePoint = point.into();

    // If bit 0 is set, negate the point
    // This matches: if (commit[0] & 1) { secp256k1_ge_neg(ge, ge) }
    if (commit[0] & 1) != 0 {
        result = -result;
    }

    Ok(result)
}

/// Save a Pedersen commitment to custom format (0x08/0x09 prefix)
///
/// Matches C code: pedersen_commitment_save() in main_impl.h:19-23
#[allow(dead_code)]
fn pedersen_commitment_save(point: &ProjectivePoint) -> Result<Vec<u8>> {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(false); // Uncompressed

    let mut result = vec![0u8; 33];

    // Extract x-coordinate
    let x_bytes = encoded.x().ok_or_else(|| VeilCryptoError::Other("Missing x coordinate".into()))?;
    result[1..33].copy_from_slice(x_bytes);

    // Check if y is a quadratic residue
    // C code: commit[0] = 9 ^ secp256k1_fe_is_quad_var(&ge->y)
    //
    // To determine if y is the canonical (QR) y:
    // 1. Compute canonical y = sqrt(x^3 + 7)
    // 2. Check if our y equals canonical y
    // 3. If yes, use 0x08; if no (meaning y = p - canonical_y), use 0x09
    use k256::FieldElement;

    let x_bytes = encoded.x().ok_or_else(|| VeilCryptoError::Other("Missing x coordinate".into()))?;
    let y_bytes = encoded.y().ok_or_else(|| VeilCryptoError::Other("Missing y coordinate".into()))?;

    let x = FieldElement::from_bytes(x_bytes.into())
        .into_option()
        .ok_or_else(|| VeilCryptoError::Other("Invalid x field element".into()))?;
    let y = FieldElement::from_bytes(y_bytes.into())
        .into_option()
        .ok_or_else(|| VeilCryptoError::Other("Invalid y field element".into()))?;

    // Compute canonical y from sqrt(x^3 + 7)
    let x_cubed = x * x * x;
    let b = FieldElement::from(7u64);
    let y_squared = x_cubed + b;
    let y_canonical = y_squared.sqrt()
        .into_option()
        .ok_or_else(|| VeilCryptoError::Other("Cannot compute sqrt for canonical y".into()))?;

    // Check if our y equals the canonical (QR) y
    let is_canonical = y == y_canonical;
    result[0] = if is_canonical { 0x08 } else { 0x09 };

    Ok(result)
}

/// Load a point from either Pedersen format (0x08/0x09) or standard compressed format (0x02/0x03)
///
/// Matches C code: load_ge() in main_impl.h:25-33 (used in prepare_mlsag)
fn load_ge(data: &[u8]) -> Result<ProjectivePoint> {
    if data.len() != 33 {
        return Err(VeilCryptoError::Other("Point must be 33 bytes".into()));
    }

    // Check if it's a Pedersen commitment (0x08 or 0x09)
    if data[0] == 0x08 || data[0] == 0x09 {
        return pedersen_commitment_load(data);
    }

    // Otherwise parse as standard compressed point (0x02/0x03)
    let encoded = EncodedPoint::from_bytes(data)
        .map_err(|_| VeilCryptoError::Other("Invalid point encoding".into()))?;

    let point = AffinePoint::from_encoded_point(&encoded)
        .into_option()
        .ok_or_else(|| VeilCryptoError::Other("Invalid point".into()))?;

    Ok(point.into())
}

/// Load a point in standard compressed format ONLY (0x02/0x03)
///
/// Matches C code: secp256k1_eckey_pubkey_parse() used in verify_mlsag
/// Does NOT accept Pedersen format (0x08/0x09)
/// Does NOT accept all-zero infinity representation (returns error like C code)
fn load_ge_standard(data: &[u8]) -> Result<ProjectivePoint> {
    if data.len() != 33 {
        return Err(VeilCryptoError::Other("Point must be 33 bytes".into()));
    }

    // Check for all-zero infinity point (matches C code behavior)
    // C code: secp256k1_eckey_pubkey_parse returns 0 if pub[0] is not 0x02 or 0x03
    if data.iter().all(|&b| b == 0) {
        return Err(VeilCryptoError::Other("Cannot parse infinity point (all zeros)".into()));
    }

    // Only accept standard compressed format (0x02/0x03)
    // Matches C: (pub[0] == SECP256K1_TAG_PUBKEY_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_ODD)
    if data[0] != 0x02 && data[0] != 0x03 {
        return Err(VeilCryptoError::Other(format!("Invalid point prefix: 0x{:02x}, expected 0x02 or 0x03", data[0])));
    }

    // Parse the point
    let encoded = EncodedPoint::from_bytes(data)
        .map_err(|e| VeilCryptoError::Other(format!("Invalid point encoding: {:?}", e)))?;

    let point = AffinePoint::from_encoded_point(&encoded)
        .into_option()
        .ok_or_else(|| VeilCryptoError::Other("Invalid point (not on curve)".into()))?;

    Ok(point.into())
}

// ============================================================================
// Main MLSAG Functions
// ============================================================================

/// Prepare MLSAG signature data
///
/// Computes the last row of the signature matrix (sum of input commitments - sum of output commitments)
/// and the blind sum for the commitment row.
///
/// Matches C code: secp256k1_prepare_mlsag() in main_impl.h:35-136
///
/// # Arguments
///
/// * `m` - Matrix buffer to update (will contain public keys + commitment row)
/// * `n_outs` - Number of output commitments
/// * `n_blinded` - Number of blinded outputs
/// * `vp_in_commits_len` - Number of input commitments (not used in C, kept for API compat)
/// * `vp_blinds_len` - Number of blinding factors (not used in C, kept for API compat)
/// * `n_cols` - Number of columns (ring size)
/// * `n_rows` - Number of rows (number of inputs + 1)
/// * `pcm_in` - Input commitments (flattened array of 33-byte commitments)
/// * `pcm_out` - Output commitments (flattened array of 33-byte commitments)
/// * `blinds` - Blinding factors (flattened array of 32-byte blinds)
///
/// # Returns
///
/// `PrepareMlsagResult` containing updated matrix M and blind sum SK
pub fn prepare_mlsag(
    m: &[u8],
    n_outs: usize,
    n_blinded: usize,
    _vp_in_commits_len: usize, // Kept for API compatibility
    _vp_blinds_len: usize,     // Kept for API compatibility
    n_cols: usize,
    n_rows: usize,
    pcm_in: &[u8],
    pcm_out: &[u8],
    blinds: &[u8],
) -> Result<PrepareMlsagResult> {
    // Validate inputs (matches C code checks)
    if n_rows < 2 || n_cols < 1 || n_outs < 1 {
        return Err(VeilCryptoError::Other("Invalid MLSAG dimensions".into()));
    }

    let n_ins = n_rows - 1; // Number of inputs
    let mut m_buf = m.to_vec();

    // Sum output commitments (C code: main_impl.h:70-78)
    let mut acc = ProjectivePoint::IDENTITY;
    for k in 0..n_outs {
        let offset = k * 33;
        if offset + 33 > pcm_out.len() {
            return Err(VeilCryptoError::Other("pcm_out buffer too small".into()));
        }
        let c = load_ge(&pcm_out[offset..offset + 33])?;
        acc += c;
    }

    // Negate (C code: secp256k1_gej_neg(&accj, &accj))
    let cno = -acc;

    // For each column (C code: main_impl.h:81-103)
    for k in 0..n_cols {
        // Sum column input commitments
        let mut acc = ProjectivePoint::IDENTITY;
        for i in 0..n_ins {
            let offset = (k + n_cols * i) * 33;
            if offset + 33 > pcm_in.len() {
                return Err(VeilCryptoError::Other("pcm_in buffer too small".into()));
            }
            let c = load_ge(&pcm_in[offset..offset + 33])?;
            acc += c;
        }

        // Subtract output commitments
        acc += cno;

        // Store in last row (nRows - 1)
        let m_offset = (k + n_cols * n_ins) * 33;
        if m_offset + 33 > m_buf.len() {
            return Err(VeilCryptoError::Other("m buffer too small".into()));
        }

        if bool::from(acc.is_identity()) {
            // With no blinds set, sum input commitments == sum output commitments
            // Store consistent infinity point (all zeros)
            m_buf[m_offset..m_offset + 33].fill(0);
        } else {
            // Serialize point as standard compressed (0x02/0x03 prefix)
            // C code: secp256k1_eckey_pubkey_serialize(..., 1) - NOT pedersen_commitment_save!
            let affine = acc.to_affine();
            let encoded = affine.to_encoded_point(true); // Compressed
            m_buf[m_offset..m_offset + 33].copy_from_slice(encoded.as_bytes());
        }
    }

    // Compute blind sum if blinds provided (C code: main_impl.h:105-134)
    let sk_buf = if !blinds.is_empty() {
        // Sum input blinds (C code: main_impl.h:109-116)
        let mut accis = Scalar::ZERO;
        for k in 0..n_ins {
            let offset = k * 32;
            if offset + 32 > blinds.len() {
                return Err(VeilCryptoError::Other("blinds buffer too small (inputs)".into()));
            }
            let mut ts_bytes = [0u8; 32];
            ts_bytes.copy_from_slice(&blinds[offset..offset + 32]);
            let ts = Scalar::from_repr(ts_bytes.into())
                .into_option()
                .ok_or_else(|| VeilCryptoError::Other("Invalid blind (overflow)".into()))?;
            accis += ts;
        }

        // Sum output blinds (C code: main_impl.h:119-126)
        let mut accos = Scalar::ZERO;
        for k in 0..n_blinded {
            let offset = (n_ins + k) * 32;
            if offset + 32 > blinds.len() {
                return Err(VeilCryptoError::Other("blinds buffer too small (outputs)".into()));
            }
            let mut ts_bytes = [0u8; 32];
            ts_bytes.copy_from_slice(&blinds[offset..offset + 32]);
            let ts = Scalar::from_repr(ts_bytes.into())
                .into_option()
                .ok_or_else(|| VeilCryptoError::Other("Invalid blind (overflow)".into()))?;
            accos += ts;
        }

        // Negate output blinds (C code: secp256k1_scalar_negate)
        accos = -accos;

        // Subtract output blinds from input blinds (C code: secp256k1_scalar_add(&ts, &accis, &accos))
        let ts = accis + accos;

        // Convert to bytes
        ts.to_bytes().to_vec()
    } else {
        vec![0u8; 32]
    };

    Ok(PrepareMlsagResult {
        m: m_buf,
        sk: sk_buf,
    })
}

/// Generate MLSAG signature
///
/// Creates a ring signature with key images for RingCT transactions.
///
/// Matches C code: secp256k1_generate_mlsag() in main_impl.h:193-384
///
/// # Arguments
///
/// * `nonce` - Nonce for randomness (32 bytes)
/// * `preimage` - Hash of transaction outputs (32 bytes)
/// * `n_cols` - Number of columns (ring size)
/// * `n_rows` - Number of rows (number of inputs + 1)
/// * `index` - Index of the real input in the ring
/// * `sk` - Secret keys (flattened array of 32-byte keys)
/// * `pk` - Public key matrix (flattened array of 33-byte compressed keys)
///
/// # Returns
///
/// `GenerateMlsagResult` containing key images, pc (c0), and ps (ss values)
pub fn generate_mlsag(
    nonce: &[u8],
    preimage: &[u8],
    n_cols: usize,
    n_rows: usize,
    index: usize,
    sk: &[u8],
    pk: &[u8],
) -> Result<GenerateMlsagResult> {
    // Validate inputs (C code: main_impl.h:214-218)
    if nonce.len() != 32 {
        return Err(VeilCryptoError::Other("nonce must be 32 bytes".into()));
    }
    if preimage.len() != 32 {
        return Err(VeilCryptoError::Other("preimage must be 32 bytes".into()));
    }
    if n_rows < 2 || n_cols < 1 || n_rows > MLSAG_MAX_ROWS {
        return Err(VeilCryptoError::Other("Invalid MLSAG dimensions".into()));
    }

    let ds_rows = n_rows - 1; // Number of rows with key images

    // Allocate output buffers
    let ki_size = ds_rows * 33;
    let pc_size = 32;
    let ps_size = n_rows * n_cols * 32;
    let mut ki_buf = vec![0u8; ki_size];
    let mut pc_buf = vec![0u8; pc_size];
    let mut ps_buf = vec![0u8; ps_size];

    // Seed the random number generator (C code: main_impl.h:222-226)
    let mut seed = Vec::new();
    seed.extend_from_slice(nonce);
    seed.extend_from_slice(preimage);
    let mut rng = HmacDrbg::new(&seed);

    // Initialize SHA256 with preimage (C code: main_impl.h:228-230)
    let mut sha256_m = Sha256::new();
    sha256_m.update(preimage);
    let sha256_pre = sha256_m.clone();

    // Generate alpha values and build initial hash (C code: main_impl.h:232-265)
    let mut alpha = vec![Scalar::ZERO; n_rows];

    // For rows with key images (ds_rows)
    for k in 0..ds_rows {
        // Generate random alpha[k] (C code: main_impl.h:233-236)
        loop {
            let tmp = rng.generate();
            if let Some(scalar) = Scalar::from_repr(tmp.into()).into_option() {
                if !bool::from(scalar.is_zero()) {
                    alpha[k] = scalar;
                    break;
                }
            }
        }

        // G * alpha[k] (C code: main_impl.h:238-243)
        let g_alpha = ProjectivePoint::mul_by_generator(&alpha[k]);
        let g_alpha_affine = g_alpha.to_affine();
        let g_alpha_bytes = g_alpha_affine.to_encoded_point(true);

        // Hash pk_ind[k] and G * alpha[k] (C code: main_impl.h:245-246)
        let pk_offset = (index + k * n_cols) * 33;
        if pk_offset + 33 > pk.len() {
            return Err(VeilCryptoError::Other("pk buffer too small".into()));
        }
        sha256_m.update(&pk[pk_offset..pk_offset + 33]);
        sha256_m.update(g_alpha_bytes.as_bytes());

        // Compute and hash key image: H(pk_ind[k]) * alpha[k] (C code: main_impl.h:248-257)
        let pk_slice = &pk[pk_offset..pk_offset + 33];
        let h_pk = hash_to_curve(pk_slice)?;
        let ki_point = h_pk * alpha[k];
        let ki_affine = ki_point.to_affine();
        let ki_bytes = ki_affine.to_encoded_point(true);
        sha256_m.update(ki_bytes.as_bytes()); // Hash H(pk) * alpha!

        // Also compute actual key image with secret key for output (C code: main_impl.h:259-264)
        let sk_offset = k * 32;
        if sk_offset + 32 > sk.len() {
            return Err(VeilCryptoError::Other("sk buffer too small".into()));
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&sk[sk_offset..sk_offset + 32]);
        let sk_scalar = Scalar::from_repr(sk_bytes.into())
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid secret key".into()))?;

        if sk_scalar.is_zero().into() {
            return Err(VeilCryptoError::Other("Secret key is zero".into()));
        }

        let ki_real = h_pk * sk_scalar;
        let ki_real_affine = ki_real.to_affine();
        let ki_real_bytes = ki_real_affine.to_encoded_point(true);

        // Store real key image in output buffer
        let ki_out_offset = k * 33;
        ki_buf[ki_out_offset..ki_out_offset + 33].copy_from_slice(ki_real_bytes.as_bytes());
    }

    // For commitment row (C code: main_impl.h:267-282)
    for k in ds_rows..n_rows {
        // Generate random alpha[k]
        loop {
            let tmp = rng.generate();
            if let Some(scalar) = Scalar::from_repr(tmp.into()).into_option() {
                if !bool::from(scalar.is_zero()) {
                    alpha[k] = scalar;
                    break;
                }
            }
        }

        // G * alpha[k]
        let g_alpha = ProjectivePoint::mul_by_generator(&alpha[k]);
        let g_alpha_affine = g_alpha.to_affine();
        let g_alpha_bytes = g_alpha_affine.to_encoded_point(true);

        // Hash pk_ind[k] and G * alpha[k]
        let pk_offset = (index + k * n_cols) * 33;
        if pk_offset + 33 > pk.len() {
            return Err(VeilCryptoError::Other("pk buffer too small".into()));
        }
        sha256_m.update(&pk[pk_offset..pk_offset + 33]);
        sha256_m.update(g_alpha_bytes.as_bytes());
    }

    // Finalize initial hash to get clast (C code: main_impl.h:284-287)
    let mut clast_bytes = [0u8; 32];
    clast_bytes.copy_from_slice(&sha256_m.finalize_reset());
    let mut clast = Scalar::from_repr(clast_bytes.into())
        .into_option()
        .ok_or_else(|| VeilCryptoError::Other("Invalid clast (overflow)".into()))?;

    if clast.is_zero().into() {
        return Err(VeilCryptoError::Other("clast is zero".into()));
    }

    // Start at next index (C code: main_impl.h:289-292)
    let mut i = (index + 1) % n_cols;
    eprintln!("[generate_mlsag] Initial clast after index column {}: {:02x?}", index, &clast_bytes[..8]);
    eprintln!("[generate_mlsag] Starting loop at column i={}", i);
    if i == 0 {
        pc_buf.copy_from_slice(&clast_bytes);
        eprintln!("[generate_mlsag] Set pc = clast (before loop)");
    }

    // Loop through all columns except index (C code: main_impl.h:294-362)
    while i != index {
        sha256_m = sha256_pre.clone();

        // For rows with key images (C code: main_impl.h:297-331)
        for k in 0..ds_rows {
            // Generate random ss (C code: main_impl.h:298-301)
            let ss = loop {
                let tmp = rng.generate();
                if let Some(scalar) = Scalar::from_repr(tmp.into()).into_option() {
                    if !bool::from(scalar.is_zero()) {
                        break scalar;
                    }
                }
            };

            // Store ss in ps buffer (C code: main_impl.h:303)
            let ps_offset = (i + k * n_cols) * 32;
            if ps_offset + 32 > ps_buf.len() {
                return Err(VeilCryptoError::Other("ps buffer too small".into()));
            }
            ps_buf[ps_offset..ps_offset + 32].copy_from_slice(&ss.to_bytes());

            // L = G * ss + pk[k][i] * clast (C code: main_impl.h:305-308)
            // C code uses secp256k1_eckey_pubkey_parse (standard format only)
            let pk_offset = (i + k * n_cols) * 33;
            if pk_offset + 33 > pk.len() {
                return Err(VeilCryptoError::Other("pk buffer too small".into()));
            }
            let pk_point = load_ge_standard(&pk[pk_offset..pk_offset + 33])?;
            let l = ProjectivePoint::mul_by_generator(&ss) + (pk_point * clast);

            // R = H(pk[k][i]) * ss + ki[k] * clast (C code: main_impl.h:311-322)
            let h_pk = hash_to_curve(&pk[pk_offset..pk_offset + 33])?;
            let h_pk_ss = h_pk * ss;

            let ki_offset = k * 33;
            // C code uses secp256k1_eckey_pubkey_parse (standard format only)
            let ki_point = load_ge_standard(&ki_buf[ki_offset..ki_offset + 33])?;
            let ki_clast = ki_point * clast;

            let r = h_pk_ss + ki_clast;

            // Hash pk[k][i], L, and R (C code: main_impl.h:324-330)
            sha256_m.update(&pk[pk_offset..pk_offset + 33]);
            let l_affine = l.to_affine();
            let l_bytes = l_affine.to_encoded_point(true);
            sha256_m.update(l_bytes.as_bytes());
            let r_affine = r.to_affine();
            let r_bytes = r_affine.to_encoded_point(true);
            sha256_m.update(r_bytes.as_bytes());
        }

        // For commitment row (C code: main_impl.h:333-351)
        for k in ds_rows..n_rows {
            // Generate random ss
            let ss = loop {
                let tmp = rng.generate();
                if let Some(scalar) = Scalar::from_repr(tmp.into()).into_option() {
                    if !bool::from(scalar.is_zero()) {
                        break scalar;
                    }
                }
            };

            // Store ss in ps buffer
            let ps_offset = (i + k * n_cols) * 32;
            if ps_offset + 32 > ps_buf.len() {
                return Err(VeilCryptoError::Other("ps buffer too small".into()));
            }
            ps_buf[ps_offset..ps_offset + 32].copy_from_slice(&ss.to_bytes());

            // L = G * ss + pk[k][i] * clast (C code: main_impl.h:341-345)
            // C code uses secp256k1_eckey_pubkey_parse (standard format only)
            let pk_offset = (i + k * n_cols) * 33;
            if pk_offset + 33 > pk.len() {
                return Err(VeilCryptoError::Other("pk buffer too small".into()));
            }
            let pk_point = load_ge_standard(&pk[pk_offset..pk_offset + 33])?;
            let l = ProjectivePoint::mul_by_generator(&ss) + (pk_point * clast);

            // Hash pk[k][i] and L
            sha256_m.update(&pk[pk_offset..pk_offset + 33]);
            let l_affine = l.to_affine();
            let l_bytes = l_affine.to_encoded_point(true);
            sha256_m.update(l_bytes.as_bytes());
        }

        // Finalize hash to get new clast (C code: main_impl.h:353-356)
        clast_bytes.copy_from_slice(&sha256_m.finalize_reset());
        clast = Scalar::from_repr(clast_bytes.into())
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid clast (overflow)".into()))?;

        if clast.is_zero().into() {
            return Err(VeilCryptoError::Other("clast is zero".into()));
        }

        eprintln!("[generate_mlsag] After processing column {}, clast: {:02x?}", i, &clast_bytes[..8]);

        // Move to next column (C code: main_impl.h:358-361)
        i = (i + 1) % n_cols;
        eprintln!("[generate_mlsag] Moving to column i={}", i);
        if i == 0 {
            pc_buf.copy_from_slice(&clast_bytes);
            eprintln!("[generate_mlsag] Set pc = clast (in loop)");
        }
    }

    // Compute ss[k][index] = alpha[k] - clast * sk[k] (C code: main_impl.h:365-378)
    for k in 0..n_rows {
        let sk_offset = k * 32;
        if sk_offset + 32 > sk.len() {
            return Err(VeilCryptoError::Other("sk buffer too small".into()));
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&sk[sk_offset..sk_offset + 32]);
        let sk_scalar = Scalar::from_repr(sk_bytes.into())
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid secret key".into()))?;

        if sk_scalar.is_zero().into() {
            return Err(VeilCryptoError::Other("Secret key is zero".into()));
        }

        // ss = alpha[k] - clast * sk[k]
        let s = clast * sk_scalar;
        let ss = alpha[k] - s;

        // Store in ps buffer
        let ps_offset = (index + k * n_cols) * 32;
        if ps_offset + 32 > ps_buf.len() {
            return Err(VeilCryptoError::Other("ps buffer too small".into()));
        }
        ps_buf[ps_offset..ps_offset + 32].copy_from_slice(&ss.to_bytes());
    }

    Ok(GenerateMlsagResult {
        key_images: ki_buf,
        pc: pc_buf,
        ps: ps_buf,
    })
}

/// Verify MLSAG signature
///
/// Verifies a ring signature with key images.
///
/// Matches C code: secp256k1_verify_mlsag() in main_impl.h:386-482
///
/// # Arguments
///
/// * `preimage` - Hash of transaction outputs (32 bytes)
/// * `n_cols` - Number of columns (ring size)
/// * `n_rows` - Number of rows (number of inputs + 1)
/// * `pk` - Public key matrix (flattened array of 33-byte compressed keys)
/// * `ki` - Key images (flattened array of 33-byte key images)
/// * `pc` - First signature component (c0, 32 bytes)
/// * `ps` - Second signature component (ss values, flattened array)
///
/// # Returns
///
/// `Ok(true)` if signature is valid, error otherwise
pub fn verify_mlsag(
    preimage: &[u8],
    n_cols: usize,
    n_rows: usize,
    pk: &[u8],
    ki: &[u8],
    pc: &[u8],
    ps: &[u8],
) -> Result<bool> {
    // Validate inputs
    if preimage.len() != 32 {
        return Err(VeilCryptoError::Other("preimage must be 32 bytes".into()));
    }
    if pc.len() != 32 {
        return Err(VeilCryptoError::Other("pc must be 32 bytes".into()));
    }

    // Validate dimensions
    if n_rows < 2 || n_cols < 1 {
        return Err(VeilCryptoError::Other("Invalid MLSAG dimensions".into()));
    }

    // Validate buffer sizes
    let expected_pk_len = n_rows * n_cols * 33;
    if pk.len() != expected_pk_len {
        return Err(VeilCryptoError::Other(format!("pk length {} doesn't match expected {} (nRows={} nCols={})", pk.len(), expected_pk_len, n_rows, n_cols)));
    }

    let ds_rows = n_rows - 1;
    let expected_ki_len = ds_rows * 33;
    if ki.len() != expected_ki_len {
        return Err(VeilCryptoError::Other(format!("ki length {} doesn't match expected {}", ki.len(), expected_ki_len)));
    }

    let expected_ps_len = n_rows * n_cols * 32;
    if ps.len() != expected_ps_len {
        return Err(VeilCryptoError::Other(format!("ps length {} doesn't match expected {}", ps.len(), expected_ps_len)));
    }

    // Parse initial challenge (C code: main_impl.h:401-404)
    let mut clast_bytes = [0u8; 32];
    clast_bytes.copy_from_slice(pc);
    let mut clast = Scalar::from_repr(clast_bytes.into())
        .into_option()
        .ok_or_else(|| VeilCryptoError::Other("Invalid pc (overflow)".into()))?;

    if clast.is_zero().into() {
        return Err(VeilCryptoError::Other("pc is zero".into()));
    }

    let c_sig = clast; // Save initial challenge for final comparison

    // Initialize SHA256 with preimage (C code: main_impl.h:408-410)
    let mut sha256_m = Sha256::new();
    sha256_m.update(preimage);
    let sha256_pre = sha256_m.clone();

    eprintln!("[verify_mlsag] Initial challenge pc: {:02x?}", &clast_bytes[..8]);
    eprintln!("[verify_mlsag] Preimage: {:02x?}", &preimage[..8]);
    eprintln!("[verify_mlsag] nCols: {}, nRows: {}", n_cols, n_rows);

    // Loop through all columns (C code: main_impl.h:412-476)
    for i in 0..n_cols {
        sha256_m = sha256_pre.clone();
        eprintln!("[verify_mlsag] Column {}: challenge = {:02x?}", i, &clast_bytes[..8]);

        // For rows with key images (C code: main_impl.h:415-449)
        for k in 0..ds_rows {
            // Parse ss (C code: main_impl.h:417-420)
            let ps_offset = (i + k * n_cols) * 32;
            if ps_offset + 32 > ps.len() {
                return Err(VeilCryptoError::Other("ps buffer too small".into()));
            }
            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(&ps[ps_offset..ps_offset + 32]);
            let ss = Scalar::from_repr(ss_bytes.into())
                .into_option()
                .ok_or_else(|| VeilCryptoError::Other("Invalid ss (overflow)".into()))?;

            if ss.is_zero().into() {
                return Err(VeilCryptoError::Other("ss is zero".into()));
            }

            // L = G * ss + pk[k][i] * clast (C code: main_impl.h:421-425)
            let pk_offset = (i + k * n_cols) * 33;
            if pk_offset + 33 > pk.len() {
                return Err(VeilCryptoError::Other("pk buffer too small".into()));
            }
            let pk_point = load_ge_standard(&pk[pk_offset..pk_offset + 33])?;
            let l = ProjectivePoint::mul_by_generator(&ss) + (pk_point * clast);

            // R = H(pk[k][i]) * ss + ki[k] * clast (C code: main_impl.h:427-440)
            let h_pk = hash_to_curve(&pk[pk_offset..pk_offset + 33])?;
            let h_pk_ss = h_pk * ss;

            let ki_offset = k * 33;
            if ki_offset + 33 > ki.len() {
                return Err(VeilCryptoError::Other("ki buffer too small".into()));
            }
            let ki_point = load_ge_standard(&ki[ki_offset..ki_offset + 33])?;
            let ki_clast = ki_point * clast;

            let r = h_pk_ss + ki_clast;

            // Hash pk[k][i], L, and R (C code: main_impl.h:442-448)
            sha256_m.update(&pk[pk_offset..pk_offset + 33]);
            let l_affine = l.to_affine();
            let l_bytes = l_affine.to_encoded_point(true);
            sha256_m.update(l_bytes.as_bytes());
            let r_affine = r.to_affine();
            let r_bytes = r_affine.to_encoded_point(true);
            sha256_m.update(r_bytes.as_bytes());

            if i < 2 {  // Only log first 2 columns to avoid spam
                eprintln!("[verify_mlsag] Col {}, Row {}: pk={:02x?}, L={:02x?}, R={:02x?}",
                    i, k, &pk[pk_offset..pk_offset+4], &l_bytes.as_bytes()[..4], &r_bytes.as_bytes()[..4]);
            }
        }

        // For commitment row (C code: main_impl.h:451-469)
        for k in ds_rows..n_rows {
            // Parse ss
            let ps_offset = (i + k * n_cols) * 32;
            if ps_offset + 32 > ps.len() {
                return Err(VeilCryptoError::Other("ps buffer too small".into()));
            }
            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(&ps[ps_offset..ps_offset + 32]);
            let ss = Scalar::from_repr(ss_bytes.into())
                .into_option()
                .ok_or_else(|| VeilCryptoError::Other("Invalid ss (overflow)".into()))?;

            if ss.is_zero().into() {
                return Err(VeilCryptoError::Other("ss is zero".into()));
            }

            // L = G * ss + pk[k][i] * clast
            let pk_offset = (i + k * n_cols) * 33;
            if pk_offset + 33 > pk.len() {
                return Err(VeilCryptoError::Other("pk buffer too small".into()));
            }
            let pk_point = load_ge_standard(&pk[pk_offset..pk_offset + 33])?;
            let l = ProjectivePoint::mul_by_generator(&ss) + (pk_point * clast);

            // Hash pk[k][i] and L
            sha256_m.update(&pk[pk_offset..pk_offset + 33]);
            let l_affine = l.to_affine();
            let l_bytes = l_affine.to_encoded_point(true);
            sha256_m.update(l_bytes.as_bytes());
        }

        // Finalize hash to get new clast (C code: main_impl.h:471-475)
        clast_bytes.copy_from_slice(&sha256_m.finalize_reset());
        clast = Scalar::from_repr(clast_bytes.into())
            .into_option()
            .ok_or_else(|| VeilCryptoError::Other("Invalid clast (overflow)".into()))?;

        if clast.is_zero().into() {
            return Err(VeilCryptoError::Other("clast is zero".into()));
        }
    }

    // Verify that clast loops back to c_sig (C code: main_impl.h:478-481)
    // The C code does: -c_sig + clast == 0?
    let initial_c_sig_bytes: [u8; 32] = c_sig.to_repr().into();
    let final_clast_bytes: [u8; 32] = clast.to_repr().into();

    let zero = clast - c_sig;

    if bool::from(zero.is_zero()) {
        Ok(true)
    } else {
        // Return detailed error with c_sig and clast values
        let error_msg = format!(
            "MLSAG verification failed: c_sig mismatch. Initial c_sig: {:02x?}, Final clast: {:02x?}",
            &initial_c_sig_bytes[..16],
            &final_clast_bytes[..16]
        );
        Err(VeilCryptoError::Other(error_msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlsag_full_roundtrip() {
        // Test vectors from Dart FFI C implementation
        // These match the output from mlsag_vector_generator.dart

        // Test parameters
        let n_cols = 3;
        let n_rows = 3;
        let n_outs = 2;
        let index = 1;

        // Prepare MLSAG inputs
        let vp_in_commits_hex = vec![
            "09abd4b09e4aa43191d5a600062fd018e425f9c84d4f49b5b6ba48ed4ad9376a34",
            "090da98ec5529b9cfafaf370be01b4a1dcca02e661d36e6e95852d873846205293",
            "098345415bcc9c3c2e50f6ac88f89936e58633354074d5486679a5f59a48f5ba8d",
            "08e461b733d5ca289e4f883d81be329bc68260889364f09e48170a40c2a8c98b9e",
            "08700bb120edc3731a54d5290281cff9b148880061823efe202f19e794a8e74900",
            "097c4a6e2dbd9557117f865264b8da6f1c21bbf4879c22e0dffa9b4757d701ef94",
        ];

        let vp_out_commits_hex = vec![
            "08af9605ae2b9bdf166c288ceb007d72eaa126ea02fcaf7058245a9f5d96340060",
            "0900dbd0ffc51aee0dd0923f2a49a52018ad523e7a2019ca3d8c1dc317e90a7e40",
        ];

        let vp_blinds_hex = vec![
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ];

        let m_input_hex = "03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f903466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2702c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee502acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        // Convert hex to bytes
        let vp_in_commits: Vec<Vec<u8>> = vp_in_commits_hex.iter().map(|h| hex::decode(h).unwrap()).collect();
        let vp_in_commits_flat: Vec<u8> = vp_in_commits.into_iter().flatten().collect();

        let vp_out_commits: Vec<Vec<u8>> = vp_out_commits_hex.iter().map(|h| hex::decode(h).unwrap()).collect();
        let vp_out_commits_flat: Vec<u8> = vp_out_commits.into_iter().flatten().collect();

        let vp_blinds: Vec<Vec<u8>> = vp_blinds_hex.iter().map(|h| hex::decode(h).unwrap()).collect();
        let vp_blinds_flat: Vec<u8> = vp_blinds.into_iter().flatten().collect();

        let m_input = hex::decode(m_input_hex).unwrap();

        // Test prepare_mlsag
        let prepare_result = prepare_mlsag(
            &m_input,
            n_outs,
            n_outs,
            vp_in_commits_hex.len(),
            vp_blinds_hex.len(),
            n_cols,
            n_rows,
            &vp_in_commits_flat,
            &vp_out_commits_flat,
            &vp_blinds_flat,
        ).expect("prepare_mlsag should succeed");

        // Expected outputs from test vector
        let expected_m = "03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f903466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2702c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee502acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe028ba43705f936a26c5af11af56fcad9e9a23d21eb2de9f6550828aa42932eb505022c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e66868099103e1fa08b58126f330ec676017f30ab119b1e0b2082a35227667f7180187d148ea";
        let expected_sk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbba766a98a26b045bf77b8e1a488bf1fcfd";

        // Extract commitment row (last 3 points of M)
        let commitment_row_offset = 6 * 33;
        let col0 = hex::encode(&prepare_result.m[commitment_row_offset..commitment_row_offset+33]);
        let col1 = hex::encode(&prepare_result.m[commitment_row_offset+33..commitment_row_offset+66]);
        let col2 = hex::encode(&prepare_result.m[commitment_row_offset+66..commitment_row_offset+99]);

        println!("\n=== Commitment Row (Rust) ===");
        println!("Column 0: {}", col0);
        println!("Column 1: {}", col1);
        println!("Column 2: {}", col2);
        println!("\n=== Expected Commitment Row (C) ===");
        println!("Column 0: 028ba43705f936a26c5af11af56fcad9e9a23d21eb2de9f6550828aa42932eb505");
        println!("Column 1: 022c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");
        println!("Column 2: 03e1fa08b58126f330ec676017f30ab119b1e0b2082a35227667f7180187d148ea");
        println!();

        assert_eq!(hex::encode(&prepare_result.m), expected_m, "prepare_mlsag M output should match");
        assert_eq!(hex::encode(&prepare_result.sk), expected_sk, "prepare_mlsag SK output should match");

        // Test generate_mlsag
        let nonce = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let preimage = hex::decode("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();

        let sk_hex = vec![
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            &expected_sk,
        ];
        let sk_bytes: Vec<Vec<u8>> = sk_hex.iter().map(|h| hex::decode(h).unwrap()).collect();
        let sk_flat: Vec<u8> = sk_bytes.into_iter().flatten().collect();

        let generate_result = generate_mlsag(
            &nonce,
            &preimage,
            n_cols,
            n_rows,
            index,
            &sk_flat,
            &prepare_result.m,
        ).expect("generate_mlsag should succeed");

        // Expected outputs from test vector
        let expected_ki = "0208d13221e3a7326a34dd45214ba80116dd142e4b5ff3ce66a8dc7bfa0378b795039075411dd82a8dec23def98a83698805b79214c695700f91bbd2821300467e59";
        let expected_pc = "f0211eeadfbeae02b99ed3582689afede1a0242dba2b9b1a73054a731403b151";
        let expected_ps = "e36507128a5404f91514ee90f6e2cf425b01cbc23dfa5ddfc7c9aeba7719026ed057cb86ba104b9c0bc51933813f9fa0d1535fd8e79163622630dc59167f8f978a9fe6a3125d3963514ca0054fe9716e92d63410fc0735f7d7c345f4b0316ced1af2114c20d570a6bdccc10a2b60322ae74734eebbe9fef7c3f33f29f4f9065f909f04f18c08a5c4a2f32d64f05db96b089442eeb71d4fe49ac01d4449cfc45346e4c6a3d37d7f2c2e01a1b2b0fd94e80932d284905e78aac76cd2a386c2b2931e2230014b1edbbfcde8efd18a91123eb494da8f66c4661f09e69af80a08e643328c459ee7b02c28978f3b08a8e3771703565d12fd306e8a3f1b6a1e69d14d4838485fbb2b45552c51a3b2fce6bd8dc68db60ea88943f591ed7c48b3ed76102a";

        // Print outputs for comparison script
        println!("\n=== MLSAG Outputs ===");
        println!("Key Images: {}", hex::encode(&generate_result.key_images));
        println!("PC (challenge): {}", hex::encode(&generate_result.pc));
        println!("PS (responses): {}", hex::encode(&generate_result.ps));
        println!("=====================\n");

        assert_eq!(hex::encode(&generate_result.key_images), expected_ki, "generate_mlsag key_images should match");
        assert_eq!(hex::encode(&generate_result.pc), expected_pc, "generate_mlsag pc should match");
        assert_eq!(hex::encode(&generate_result.ps), expected_ps, "generate_mlsag ps should match");

        // Test verify_mlsag
        let verify_result = verify_mlsag(
            &preimage,
            n_cols,
            n_rows,
            &prepare_result.m,
            &generate_result.key_images,
            &generate_result.pc,
            &generate_result.ps,
        );

        assert!(verify_result.is_ok(), "verify_mlsag should succeed");
        assert!(verify_result.unwrap(), "MLSAG signature should be valid");
    }
}
