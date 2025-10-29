//! Test HMAC-DRBG Compatibility with Veil's secp256k1 Implementation
//!
//! This test verifies that our pure Rust HmacDrbg produces identical output
//! to Veil Core's secp256k1_rfc6979_hmac_sha256_* functions.
//!
//! To verify:
//! 1. Run this test: `cargo test test_hmac_drbg_compat -- --nocapture`
//! 2. Compile and run the C test: `test_hmac_drbg_c`
//! 3. Compare outputs byte-by-byte

use veil_crypto::rangeproof::HmacDrbg;
use hex;

#[test]
fn test_hmac_drbg_compat() {
    println!("\n========================================");
    println!("HMAC-DRBG Compatibility Test - Rust");
    println!("========================================\n");

    // Test vectors matching C test program
    let test_vectors = vec![
        (
            "Test 1: All 0xff nonce + all 0xee preimage",
            vec![0xffu8; 32],
            vec![0xeeu8; 32],
        ),
        (
            "Test 2: All zeros",
            vec![0x00u8; 32],
            vec![0x00u8; 32],
        ),
        (
            "Test 3: Incrementing bytes",
            (0..32).collect::<Vec<u8>>(),
            (32..64).collect::<Vec<u8>>(),
        ),
        (
            "Test 4: MLSAG example (from actual transaction)",
            hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap(),
            hex::decode("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap(),
        ),
    ];

    for (desc, nonce, preimage) in test_vectors {
        println!("\n{}", desc);
        println!("{}", "=".repeat(desc.len()));
        println!("Nonce:    {}", hex::encode(&nonce));
        println!("Preimage: {}", hex::encode(&preimage));

        // Build seed: nonce || preimage (64 bytes total)
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&nonce);
        seed.extend_from_slice(&preimage);
        println!("Seed:     {} ({} bytes)", hex::encode(&seed), seed.len());

        // Initialize DRBG
        let mut drbg = HmacDrbg::new(&seed);

        // Generate first 10 random values
        println!("\nFirst 10 random values:");
        for i in 0..10 {
            let random = drbg.generate();
            println!("Random[{:2}]: {}", i, hex::encode(&random));
        }
        println!();
    }

    println!("\n========================================");
    println!("Compare with C test output!");
    println!("========================================\n");
}

#[test]
fn test_hmac_drbg_state_after_init() {
    // Test initial state matches C implementation
    let seed = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                            eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();

    let mut drbg = HmacDrbg::new(&seed);

    // After initialization, the internal state should match C
    // We can verify this by generating values and comparing with C output
    let first = drbg.generate();
    println!("First random after init: {}", hex::encode(&first));

    // Expected from C (to be filled in after running C test)
    // let expected = hex::decode("...").unwrap();
    // assert_eq!(first.as_slice(), &expected);
}

#[test]
fn test_hmac_drbg_retry_behavior() {
    // Test that retry flag works correctly
    let seed = vec![0x42u8; 64];
    let mut drbg = HmacDrbg::new(&seed);

    println!("\nTesting retry behavior:");

    // First generate (retry should be false initially, true after)
    let r1 = drbg.generate();
    println!("Generate 1: {}", hex::encode(&r1));

    // Second generate (retry should be true)
    let r2 = drbg.generate();
    println!("Generate 2: {}", hex::encode(&r2));

    // Third generate
    let r3 = drbg.generate();
    println!("Generate 3: {}", hex::encode(&r3));

    // All values should be different
    assert_ne!(r1, r2);
    assert_ne!(r2, r3);
    assert_ne!(r1, r3);
}
