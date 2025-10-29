// Test that Pedersen format loading matches C behavior

use hex;

#[test]
fn test_pedersen_point_loading() {
    use k256::{AffinePoint, EncodedPoint};
    use k256::elliptic_curve::sec1::FromEncodedPoint;

    // Test with the exact points from our MLSAG test
    let test_points = [
        ("09abd4b09e4aa43191d5a600062fd018e425f9c84d4f49b5b6ba48ed4ad9376a34", "03abd4b09e4aa43191d5a600062fd018e425f9c84d4f49b5b6ba48ed4ad9376a34"),
        ("08e461b733d5ca289e4f883d81be329bc68260889364f09e48170a40c2a8c98b9e", "02e461b733d5ca289e4f883d81be329bc68260889364f09e48170a40c2a8c98b9e"),
        ("08af9605ae2b9bdf166c288ceb007d72eaa126ea02fcaf7058245a9f5d96340060", "02af9605ae2b9bdf166c288ceb007d72eaa126ea02fcaf7058245a9f5d96340060"),
        ("0900dbd0ffc51aee0dd0923f2a49a52018ad523e7a2019ca3d8c1dc317e90a7e40", "0300dbd0ffc51aee0dd0923f2a49a52018ad523e7a2019ca3d8c1dc317e90a7e40"),
    ];

    for (pedersen_hex, expected_standard_hex) in &test_points {
        let pedersen = hex::decode(pedersen_hex).unwrap();

        // Our conversion: 0x08 -> 0x02, 0x09 -> 0x03
        let mut standard = pedersen.clone();
        standard[0] = if pedersen[0] == 0x08 { 0x02 } else { 0x03 };

        println!("Pedersen:  {}", pedersen_hex);
        println!("Converted: {}", hex::encode(&standard));
        println!("Expected:  {}", expected_standard_hex);

        assert_eq!(hex::encode(&standard), *expected_standard_hex, "Conversion should match");

        // Try to load as a point
        let encoded = EncodedPoint::from_bytes(&standard).expect("Should parse");
        let point = AffinePoint::from_encoded_point(&encoded);
        assert!(bool::from(point.is_some()), "Should be a valid point");

        println!("✓ Point loads successfully\n");
    }
}
