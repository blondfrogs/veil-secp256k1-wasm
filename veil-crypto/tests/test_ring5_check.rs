use k256::{Scalar, ProjectivePoint, elliptic_curve::{ops::MulByGenerator, PrimeField, sec1::ToEncodedPoint}};

#[test]
fn test_ring5_commitment() {
    // sec[5] from HMAC-DRBG (verified to match C)
    let sec5_hex = "56d1f0fe27746aae8deb50b5530e08046930fba6c244af33eddc0e7b89ce8b82";
    let sec5_bytes = hex::decode(sec5_hex).unwrap();
    let mut sec5_array = [0u8; 32];
    sec5_array.copy_from_slice(&sec5_bytes);

    let sec5 = Scalar::from_repr(sec5_array.into()).unwrap();

    // Compute sec[5] * G (no H component since value_part=0)
    let commitment = ProjectivePoint::mul_by_generator(&sec5);
    let affine = commitment.to_affine();

    let serialized = affine.to_encoded_point(true);
    let bytes = serialized.as_bytes();

    println!("\n=== Rust k256 Ring 5 Commitment ===");
    println!("sec[5] * G = {}", hex::encode(bytes));
    println!("Y-coordinate parity: {:#04x} ({} y)", bytes[0],
             if bytes[0] == 0x02 { "even" } else { "odd" });

    // C secp256k1 produces:
    // 02302960906739320b7035f9c543488884f0297206e3bb0c01a35400c2185d1bdf
    let c_expected = "02302960906739320b7035f9c543488884f0297206e3bb0c01a35400c2185d1bdf";
    let matches_c = hex::encode(bytes) == c_expected;

    println!("\nC secp256k1 result: {}", c_expected);
    println!("Match: {}", if matches_c { "YES ✅" } else { "NO ❌" });

    // This SHOULD pass - both implementations agree on even y
    assert_eq!(bytes[0], 0x02, "Expected even y (0x02)");
    assert_eq!(hex::encode(bytes), c_expected, "Should match C exactly");
}
