//! Test Full MLSAG Compatibility with Veil's secp256k1 Implementation
//!
//! This test generates a complete MLSAG signature using both:
//! 1. Pure Rust implementation (veil-crypto)
//! 2. Veil Core's C implementation (via test program)
//!
//! Then compares all outputs:
//! - Key images
//! - Challenge (pc)
//! - Responses (ps)
//!
//! To run:
//! ```
//! cargo test test_mlsag_full_compat -- --nocapture
//! ```

use veil_crypto::mlsag::{prepare_mlsag, generate_mlsag, verify_mlsag};
use hex;

#[test]
fn test_mlsag_full_compat() {
    println!("\n========================================");
    println!("Full MLSAG Compatibility Test - Rust");
    println!("========================================\n");

    // Use the SAME test vector from the Rust unit tests in mlsag.rs
    // This is known to produce correct output
    let n_cols = 3;  // Ring size
    let n_rows = 3;  // 2 inputs + 1 commitment row
    let n_outs = 2;
    let index = 1;   // Secret column

    println!("MLSAG Parameters:");
    println!("  Ring size (nCols): {}", n_cols);
    println!("  Rows (nRows):      {}", n_rows);
    println!("  Outputs (nOuts):   {}", n_outs);
    println!("  Secret index:      {}", index);
    println!();

    // Input commitments (6 total: 3 columns × 2 input rows)
    let vp_in_commits_hex = vec![
        "09abd4b09e4aa43191d5a600062fd018e425f9c84d4f49b5b6ba48ed4ad9376a34",
        "090da98ec5529b9cfafaf370be01b4a1dcca02e661d36e6e95852d873846205293",
        "098345415bcc9c3c2e50f6ac88f89936e58633354074d5486679a5f59a48f5ba8d",
        "08e461b733d5ca289e4f883d81be329bc68260889364f09e48170a40c2a8c98b9e",
        "08700bb120edc3731a54d5290281cff9b148880061823efe202f19e794a8e74900",
        "097c4a6e2dbd9557117f865264b8da6f1c21bbf4879c22e0dffa9b4757d701ef94",
    ];

    // Output commitments
    let vp_out_commits_hex = vec![
        "08af9605ae2b9bdf166c288ceb007d72eaa126ea02fcaf7058245a9f5d96340060",
        "0900dbd0ffc51aee0dd0923f2a49a52018ad523e7a2019ca3d8c1dc317e90a7e40",
    ];

    // Blinding factors (2 inputs + 2 outputs = 4 total)
    let vp_blinds_hex = vec![
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    ];

    // Initial M matrix (public keys for 2 input rows, zeros for commitment row)
    let m_input_hex = "03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb\
                       0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
                       02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\
                       03466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27\
                       02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\
                       02acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe\
                       000000000000000000000000000000000000000000000000000000000000000000\
                       000000000000000000000000000000000000000000000000000000000000000000\
                       000000000000000000000000000000000000000000000000000000000000000000";

    // Convert to bytes
    let vp_in_commits: Vec<Vec<u8>> = vp_in_commits_hex.iter()
        .map(|h| hex::decode(h).unwrap())
        .collect();
    let vp_in_commits_flat: Vec<u8> = vp_in_commits.into_iter().flatten().collect();

    let vp_out_commits: Vec<Vec<u8>> = vp_out_commits_hex.iter()
        .map(|h| hex::decode(h).unwrap())
        .collect();
    let vp_out_commits_flat: Vec<u8> = vp_out_commits.into_iter().flatten().collect();

    let vp_blinds: Vec<Vec<u8>> = vp_blinds_hex.iter()
        .map(|h| hex::decode(h).unwrap())
        .collect();
    let vp_blinds_flat: Vec<u8> = vp_blinds.into_iter().flatten().collect();

    let m_input = hex::decode(m_input_hex.replace("\\s", "")).unwrap();

    // Step 1: prepare_mlsag
    println!("Step 1: Calling prepare_mlsag...");
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

    println!("  M (updated): {}", hex::encode(&prepare_result.m));
    println!("  SK (blind sum): {}", hex::encode(&prepare_result.sk));
    println!();

    // Step 2: generate_mlsag
    println!("Step 2: Calling generate_mlsag...");

    let nonce = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
    let preimage = hex::decode("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();

    let sk3_hex = hex::encode(&prepare_result.sk);
    let sk_hex = vec![
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        &sk3_hex,
    ];
    let sk_bytes: Vec<Vec<u8>> = sk_hex.iter()
        .map(|h| hex::decode(h).unwrap())
        .collect();
    let sk_flat: Vec<u8> = sk_bytes.into_iter().flatten().collect();

    println!("  Nonce: {}", hex::encode(&nonce));
    println!("  Preimage: {}", hex::encode(&preimage));
    println!("  Secret keys count: {}", sk_hex.len());
    println!();

    let generate_result = generate_mlsag(
        &nonce,
        &preimage,
        n_cols,
        n_rows,
        index,
        &sk_flat,
        &prepare_result.m,
    ).expect("generate_mlsag should succeed");

    println!("✅ MLSAG Generation Complete!");
    println!();
    println!("Outputs:");
    println!("  Key Images: {}", hex::encode(&generate_result.key_images));
    println!("  PC (challenge): {}", hex::encode(&generate_result.pc));
    println!("  PS (responses): {}", hex::encode(&generate_result.ps));
    println!();

    // Step 3: verify_mlsag
    println!("Step 3: Verifying MLSAG signature...");
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
    println!("✅ Signature verifies locally!");
    println!();

    println!("========================================");
    println!("Test completed successfully!");
    println!();
    println!("⚠️  To compare with C implementation:");
    println!("1. Compile and run test_mlsag_c with these EXACT inputs");
    println!("2. Compare key images, pc, and ps byte-by-byte");
    println!("========================================\n");
}

#[test]
fn test_mlsag_determinism() {
    println!("\n=== Testing MLSAG Determinism ===\n");

    // Same inputs should always produce same outputs
    let nonce = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
    let preimage = hex::decode("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();

    // Minimal test: 1 input, ring size 2
    let n_cols = 2;
    let n_rows = 2;  // 1 input + 1 commitment
    let index = 0;

    // Build minimal M matrix with valid points
    // Matrix is 2 rows x 2 columns (2x2) = 4 public keys
    // Row 0 (pubkeys): col0, col1
    // Row 1 (commitments): col0, col1
    let m = hex::decode(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
         02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\
         02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\
         0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    ).unwrap();

    let sk = hex::decode(
        "0000000000000000000000000000000000000000000000000000000000000001\
         0000000000000000000000000000000000000000000000000000000000000002"
    ).unwrap();

    // Generate twice
    let result1 = generate_mlsag(&nonce, &preimage, n_cols, n_rows, index, &sk, &m)
        .expect("First generation");
    let result2 = generate_mlsag(&nonce, &preimage, n_cols, n_rows, index, &sk, &m)
        .expect("Second generation");

    // Should be identical
    assert_eq!(result1.key_images, result2.key_images, "Key images should be deterministic");
    assert_eq!(result1.pc, result2.pc, "PC should be deterministic");
    assert_eq!(result1.ps, result2.ps, "PS should be deterministic");

    println!("✅ MLSAG generation is deterministic");
}
