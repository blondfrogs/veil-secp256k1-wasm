//! Veil WASM Bindings
//!
//! WebAssembly bindings for the Veil crypto library.
//! Exposes the pure Rust functions to JavaScript/TypeScript.

use wasm_bindgen::prelude::*;
use veil_crypto::{self, VeilCryptoError};

/// Initialize panic hook for better error messages in the browser
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Convert VeilCryptoError to JsValue
fn to_js_error(err: VeilCryptoError) -> JsValue {
    JsValue::from_str(&format!("{}", err))
}

// ============================================================================
// Key Image Operations
// ============================================================================

/// Generate a key image from a public key and secret key
///
/// # Arguments
///
/// * `pk_bytes` - Public key (33 bytes compressed)
/// * `sk_bytes` - Secret key (32 bytes)
///
/// # Returns
///
/// Key image as a Uint8Array (33 bytes)
///
/// # Errors
///
/// Throws JavaScript error if the operation fails
#[wasm_bindgen(js_name = getKeyImage)]
pub fn get_keyimage(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    // Pass raw bytes directly - veil_crypto validates internally
    veil_crypto::keyimage::get_keyimage(pk_bytes, sk_bytes).map_err(to_js_error)
}

// ============================================================================
// ECDH Operations
// ============================================================================

/// Perform ECDH_VEIL to generate a shared secret
///
/// # Arguments
///
/// * `pubkey_bytes` - Public key (33 or 65 bytes)
/// * `privkey_bytes` - Private key (32 bytes)
///
/// # Returns
///
/// Shared secret as a Uint8Array (32 bytes)
#[wasm_bindgen(js_name = ecdhVeil)]
pub fn ecdh_veil(pubkey_bytes: &[u8], privkey_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    // Pass raw bytes directly - veil_crypto validates internally
    veil_crypto::ecdh::ecdh_veil(pubkey_bytes, privkey_bytes).map_err(to_js_error)
}

// ============================================================================
// Pedersen Commitment Operations
// ============================================================================

/// Create a Pedersen commitment
///
/// # Arguments
///
/// * `value` - The value to commit to
/// * `blind` - Blinding factor (32 bytes)
///
/// # Returns
///
/// Commitment as a Uint8Array (33 bytes)
#[wasm_bindgen(js_name = pedersenCommit)]
pub fn pedersen_commit(value: u64, blind: &[u8]) -> Result<Vec<u8>, JsValue> {
    veil_crypto::pedersen::pedersen_commit(value, blind).map_err(to_js_error)
}

/// Sum blinding factors for balance proof
///
/// # Arguments
///
/// * `blinds` - Array of blinding factors (as JSON array of hex strings)
/// * `n_positive` - Number of positive blinds
///
/// # Returns
///
/// Resulting blind as a Uint8Array (32 bytes)
#[wasm_bindgen(js_name = pedersenBlindSum)]
pub fn pedersen_blind_sum(blinds_json: &str, n_positive: usize) -> Result<Vec<u8>, JsValue> {
    // Parse JSON array of hex strings
    let blinds_hex: Vec<String> = serde_json::from_str(blinds_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JSON: {}", e)))?;

    let blinds: Vec<Vec<u8>> = blinds_hex
        .iter()
        .map(|s| hex::decode(s).map_err(|e| format!("Invalid hex: {}", e)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&e))?;

    veil_crypto::pedersen::pedersen_blind_sum(&blinds, n_positive).map_err(to_js_error)
}

// ============================================================================
// Range Proof Operations
// ============================================================================

/// Sign a range proof
///
/// # Arguments
///
/// * `commitment` - Pre-computed Pedersen commitment (33 bytes hex or bytes)
/// * `value` - The value to prove
/// * `blind` - Blinding factor (32 bytes)
/// * `nonce` - Nonce for rewinding (32 or 33 bytes, typically the commitment)
/// * `message` - Optional message to embed (max 256 bytes, pass empty for none)
/// * `min_value` - Minimum value for range (typically 0)
/// * `exp` - Base-10 exponent (-1 for auto)
/// * `min_bits` - Minimum bits to prove (0 for auto)
///
/// # Returns
///
/// JSON object with { proof, commitment, blind, nonce }
#[wasm_bindgen(js_name = rangeproofSign)]
pub fn rangeproof_sign(
    commitment: &[u8],
    value: u64,
    blind: &[u8],
    nonce: &[u8],
    message: &[u8],
    min_value: u64,
    exp: i32,
    min_bits: i32,
) -> Result<String, JsValue> {
    let message_opt = if message.is_empty() {
        None
    } else {
        Some(message)
    };

    let result = veil_crypto::rangeproof::rangeproof_sign(
        commitment, value, blind, nonce, message_opt, min_value, exp, min_bits,
    )
    .map_err(to_js_error)?;

    let json = serde_json::json!({
        "proof": hex::encode(&result.proof),
        "commitment": hex::encode(&result.commitment),
        "blind": hex::encode(&result.blind),
        "nonce": hex::encode(&result.nonce),
    });

    Ok(json.to_string())
}

/// Verify a range proof
///
/// # Arguments
///
/// * `commitment` - Pedersen commitment (33 bytes)
/// * `proof` - Range proof
///
/// # Returns
///
/// JSON object with { minValue, maxValue } if valid, error otherwise
#[wasm_bindgen(js_name = rangeproofVerify)]
pub fn rangeproof_verify(commitment: &[u8], proof: &[u8]) -> Result<String, JsValue> {
    let result = veil_crypto::rangeproof::rangeproof_verify(commitment, proof).map_err(to_js_error)?;

    let json = serde_json::json!({
        "minValue": result.min_value,
        "maxValue": result.max_value,
    });

    Ok(json.to_string())
}

/// Rewind a range proof to extract value
///
/// # Arguments
///
/// * `nonce` - Nonce used in proof (32 bytes)
/// * `commitment` - Pedersen commitment (33 bytes)
/// * `proof` - Range proof
///
/// # Returns
///
/// JSON object with { blind, value, minValue, maxValue, message }
#[wasm_bindgen(js_name = rangeproofRewind)]
pub fn rangeproof_rewind(
    nonce: &[u8],
    commitment: &[u8],
    proof: &[u8],
) -> Result<String, JsValue> {
    let result =
        veil_crypto::rangeproof::rangeproof_rewind(nonce, commitment, proof).map_err(to_js_error)?;

    let json = serde_json::json!({
        "blind": hex::encode(&result.blind),
        "value": result.value,
        "minValue": result.min_value,
        "maxValue": result.max_value,
        "message": hex::encode(&result.message),
    });

    Ok(json.to_string())
}

// ============================================================================
// MLSAG Operations
// ============================================================================

/// Prepare MLSAG signature data
///
/// # Arguments
///
/// * `m` - Matrix buffer (hex string)
/// * `n_outs` - Number of output commitments
/// * `n_blinded` - Number of blinded outputs
/// * `vp_in_commits_len` - Number of input commitments
/// * `vp_blinds_len` - Number of blinding factors
/// * `n_cols` - Number of columns (ring size)
/// * `n_rows` - Number of rows (inputs + 1)
/// * `pcm_in` - Input commitments (JSON array of hex strings)
/// * `pcm_out` - Output commitments (JSON array of hex strings)
/// * `blinds` - Blinding factors (JSON array of hex strings)
///
/// # Returns
///
/// JSON object with { m, sk } as hex strings
#[wasm_bindgen(js_name = prepareMlsag)]
pub fn prepare_mlsag(
    m_hex: &str,
    n_outs: usize,
    n_blinded: usize,
    vp_in_commits_len: usize,
    vp_blinds_len: usize,
    n_cols: usize,
    n_rows: usize,
    pcm_in_json: &str,
    pcm_out_json: &str,
    blinds_json: &str,
) -> Result<String, JsValue> {
    // Decode M
    let m = hex::decode(m_hex).map_err(|e| JsValue::from_str(&format!("Invalid m hex: {}", e)))?;

    // Parse and decode input commitments
    let pcm_in_hex: Vec<String> = serde_json::from_str(pcm_in_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid pcm_in JSON: {}", e)))?;
    let pcm_in_bytes: Vec<Vec<u8>> = pcm_in_hex
        .iter()
        .map(|s| hex::decode(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid pcm_in hex: {}", e)))?;
    let pcm_in_flat: Vec<u8> = pcm_in_bytes.into_iter().flatten().collect();

    // Parse and decode output commitments
    let pcm_out_hex: Vec<String> = serde_json::from_str(pcm_out_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid pcm_out JSON: {}", e)))?;
    let pcm_out_bytes: Vec<Vec<u8>> = pcm_out_hex
        .iter()
        .map(|s| hex::decode(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid pcm_out hex: {}", e)))?;
    let pcm_out_flat: Vec<u8> = pcm_out_bytes.into_iter().flatten().collect();

    // Parse and decode blinds
    let blinds_hex: Vec<String> = serde_json::from_str(blinds_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid blinds JSON: {}", e)))?;
    let blinds_bytes: Vec<Vec<u8>> = blinds_hex
        .iter()
        .map(|s| hex::decode(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid blinds hex: {}", e)))?;
    let blinds_flat: Vec<u8> = blinds_bytes.into_iter().flatten().collect();

    // Call the function
    let result = veil_crypto::mlsag::prepare_mlsag(
        &m,
        n_outs,
        n_blinded,
        vp_in_commits_len,
        vp_blinds_len,
        n_cols,
        n_rows,
        &pcm_in_flat,
        &pcm_out_flat,
        &blinds_flat,
    )
    .map_err(to_js_error)?;

    let json = serde_json::json!({
        "m": hex::encode(&result.m),
        "sk": hex::encode(&result.sk),
    });

    Ok(json.to_string())
}

/// Generate MLSAG signature
///
/// # Arguments
///
/// * `nonce` - Nonce for randomness (hex string, 32 bytes)
/// * `preimage` - Hash of transaction outputs (hex string, 32 bytes)
/// * `n_cols` - Number of columns (ring size)
/// * `n_rows` - Number of rows (inputs + 1)
/// * `index` - Index of real input in ring
/// * `sk` - Secret keys (JSON array of hex strings)
/// * `pk` - Public key matrix (hex string)
///
/// # Returns
///
/// JSON object with { keyImages, pc, ps } as hex strings
#[wasm_bindgen(js_name = generateMlsag)]
pub fn generate_mlsag(
    nonce_hex: &str,
    preimage_hex: &str,
    n_cols: usize,
    n_rows: usize,
    index: usize,
    sk_json: &str,
    pk_hex: &str,
) -> Result<String, JsValue> {
    // Decode nonce and preimage
    let nonce =
        hex::decode(nonce_hex).map_err(|e| JsValue::from_str(&format!("Invalid nonce hex: {}", e)))?;
    let preimage = hex::decode(preimage_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid preimage hex: {}", e)))?;

    // Parse and decode secret keys
    let sk_hex: Vec<String> = serde_json::from_str(sk_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid sk JSON: {}", e)))?;
    let sk_bytes: Vec<Vec<u8>> = sk_hex
        .iter()
        .map(|s| hex::decode(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid sk hex: {}", e)))?;
    let sk_flat: Vec<u8> = sk_bytes.into_iter().flatten().collect();

    // Decode public key matrix
    let pk = hex::decode(pk_hex).map_err(|e| JsValue::from_str(&format!("Invalid pk hex: {}", e)))?;

    // Call the function
    let result = veil_crypto::mlsag::generate_mlsag(&nonce, &preimage, n_cols, n_rows, index, &sk_flat, &pk)
        .map_err(to_js_error)?;

    let json = serde_json::json!({
        "keyImages": hex::encode(&result.key_images),
        "pc": hex::encode(&result.pc),
        "ps": hex::encode(&result.ps),
    });

    Ok(json.to_string())
}

/// Verify MLSAG signature
///
/// # Arguments
///
/// * `preimage` - Hash of transaction outputs (hex string, 32 bytes)
/// * `n_cols` - Number of columns (ring size)
/// * `n_rows` - Number of rows (inputs + 1)
/// * `pk` - Public key matrix (hex string)
/// * `ki` - Key images (hex string)
/// * `pc` - First signature component (hex string, 32 bytes)
/// * `ps` - Second signature component (hex string)
///
/// # Returns
///
/// JSON object with { valid: true/false }
#[wasm_bindgen(js_name = verifyMlsag)]
pub fn verify_mlsag(
    preimage_hex: &str,
    n_cols: usize,
    n_rows: usize,
    pk_hex: &str,
    ki_hex: &str,
    pc_hex: &str,
    ps_hex: &str,
) -> Result<String, JsValue> {
    // Decode all parameters
    let preimage = hex::decode(preimage_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid preimage hex: {}", e)))?;
    let pk = hex::decode(pk_hex).map_err(|e| JsValue::from_str(&format!("Invalid pk hex: {}", e)))?;
    let ki = hex::decode(ki_hex).map_err(|e| JsValue::from_str(&format!("Invalid ki hex: {}", e)))?;
    let pc = hex::decode(pc_hex).map_err(|e| JsValue::from_str(&format!("Invalid pc hex: {}", e)))?;
    let ps = hex::decode(ps_hex).map_err(|e| JsValue::from_str(&format!("Invalid ps hex: {}", e)))?;

    // Call the function
    let valid =
        veil_crypto::mlsag::verify_mlsag(&preimage, n_cols, n_rows, &pk, &ki, &pc, &ps).map_err(to_js_error)?;

    let json = serde_json::json!({
        "valid": valid,
    });

    Ok(json.to_string())
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Hash data with SHA256
#[wasm_bindgen(js_name = hashSha256)]
pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    veil_crypto::utils::hash_sha256(data).to_vec()
}

/// Hash data with Keccak256
#[wasm_bindgen(js_name = hashKeccak256)]
pub fn hash_keccak256(data: &[u8]) -> Vec<u8> {
    veil_crypto::utils::hash_keccak256(data).to_vec()
}

// ============================================================================
// Elliptic Curve Operations
// ============================================================================

/// Derive a public key from a secret key
///
/// # Arguments
///
/// * `secret` - Secret key (32 bytes)
///
/// # Returns
///
/// Public key as a Uint8Array (33 bytes compressed)
#[wasm_bindgen(js_name = derivePubkey)]
pub fn derive_pubkey(secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    veil_crypto::derive_pubkey(secret).map_err(to_js_error)
}

/// Add a scalar * G to a public key point
///
/// result = pubkey + (scalar * G)
///
/// # Arguments
///
/// * `pubkey` - Public key (33 bytes compressed)
/// * `scalar` - Scalar value (32 bytes)
///
/// # Returns
///
/// Resulting public key as a Uint8Array (33 bytes)
#[wasm_bindgen(js_name = pointAddScalar)]
pub fn point_add_scalar(pubkey: &[u8], scalar: &[u8]) -> Result<Vec<u8>, JsValue> {
    veil_crypto::point_add_scalar(pubkey, scalar).map_err(to_js_error)
}

/// Multiply a public key point by a scalar
///
/// result = scalar * pubkey
///
/// # Arguments
///
/// * `pubkey` - Public key (33 bytes compressed)
/// * `scalar` - Scalar value (32 bytes)
///
/// # Returns
///
/// Resulting public key as a Uint8Array (33 bytes)
#[wasm_bindgen(js_name = pointMultiply)]
pub fn point_multiply(pubkey: &[u8], scalar: &[u8]) -> Result<Vec<u8>, JsValue> {
    veil_crypto::point_multiply(pubkey, scalar).map_err(to_js_error)
}

/// Add two private keys (mod curve order)
///
/// result = (a + b) mod n
///
/// # Arguments
///
/// * `a` - First secret key (32 bytes)
/// * `b` - Second secret key (32 bytes)
///
/// # Returns
///
/// Resulting secret key as a Uint8Array (32 bytes)
#[wasm_bindgen(js_name = privateAdd)]
pub fn private_add(a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    veil_crypto::private_add(a, b).map_err(to_js_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_init_works() {
        // Just check that initialization doesn't panic
        init_panic_hook();
    }

    #[wasm_bindgen_test]
    fn test_hash_sha256_works() {
        let data = b"hello world";
        let hash = hash_sha256(data);
        assert_eq!(hash.len(), 32);
    }
}
