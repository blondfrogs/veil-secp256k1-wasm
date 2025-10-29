#[test]
fn test_various_values() {
    use veil_crypto::pedersen::pedersen_commit;
    use veil_crypto::rangeproof::{rangeproof_sign, rangeproof_verify};

    let blind = hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
    let nonce = hex::decode("2222222222222222222222222222222222222222222222222222222222222222").unwrap();

    let test_values = vec![
        (1u64, "value=1"),
        (100u64, "value=100"),
        (12345u64, "value=12345 (passing test)"),
        (1000000u64, "value=1M"),
        (1000000000u64, "value=1B (failing test)"),
    ];

    for (value, label) in test_values {
        println!("\n=== Testing {} ===", label);

        let commitment = pedersen_commit(value, &blind).unwrap();

        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            None,  // No message to isolate value issue
            0,
            2,
            32,
        );

        if sign_result.is_err() {
            println!("❌ SIGN FAILED: {:?}", sign_result.err());
            continue;
        }

        let proof = sign_result.unwrap().proof;
        println!("✅ Proof created, length: {}", proof.len());

        let verify_result = rangeproof_verify(&commitment, &proof);
        match verify_result {
            Ok(_) => println!("✅ Verification PASSED"),
            Err(e) => println!("❌ Verification FAILED: {}", e),
        }
    }
}
