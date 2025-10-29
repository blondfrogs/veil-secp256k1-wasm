#[test]
fn test_value_message_combinations() {
    use veil_crypto::pedersen::pedersen_commit;
    use veil_crypto::rangeproof::{rangeproof_sign, rangeproof_verify};

    let blind = hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
    let nonce = hex::decode("2222222222222222222222222222222222222222222222222222222222222222").unwrap();

    let test_cases = vec![
        (1u64, None, "value=1, no message"),
        (1u64, Some(&b"one"[..]), "value=1, with message (original failing test)"),
        (100u64, None, "value=100, no message"),
        (100u64, Some(&b"test"[..]), "value=100, with message"),
        (12345u64, None, "value=12345, no message (original passing test)"),
        (1000000000u64, None, "value=1B, no message"),
        (1000000000u64, Some(&b"large value test"[..]), "value=1B, with message (original failing test)"),
    ];

    for (value, message, label) in test_cases {
        println!("\n=== {} ===", label);

        let commitment = pedersen_commit(value, &blind).unwrap();

        let sign_result = rangeproof_sign(
            &commitment,
            value,
            &blind,
            &nonce,
            message,
            0,
            2,
            32,
        );

        if sign_result.is_err() {
            println!("❌ SIGN FAILED: {:?}", sign_result.err());
            continue;
        }

        let proof = sign_result.unwrap().proof;

        let verify_result = rangeproof_verify(&commitment, &proof);
        match verify_result {
            Ok(_) => println!("✅ PASSED"),
            Err(e) => println!("❌ FAILED: {}", e),
        }
    }
}
