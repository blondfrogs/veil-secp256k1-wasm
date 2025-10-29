use veil_crypto::pedersen::get_generator_h_point;
use k256::AffinePoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;

fn serialize_point_custom(point: &AffinePoint) -> [u8; 33] {
    let encoded = point.to_encoded_point(true); // SEC1 compressed format
    let bytes = encoded.as_bytes();
    let mut result = [0u8; 33];

    // Convert SEC1 format (0x02/0x03) to C custom format (0x00/0x01)
    result[0] = if bytes[0] == 0x02 { 0x00 } else { 0x01 };
    result[1..33].copy_from_slice(&bytes[1..33]); // x-coordinate

    result
}

#[test]
fn test_h_generator_serialization() {
    // Get our H generator
    let h = get_generator_h_point().unwrap().to_affine();
    
    // Serialize it
    let serialized = serialize_point_custom(&h);
    
    // Expected from Dart/Flutter code
    let expected = [
        0x00, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b,
        0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96,
        0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    ];
    
    println!("\nH Generator Serialization Test:");
    println!("Expected (Dart): {}", hex::encode(&expected));
    println!("Our code:        {}", hex::encode(&serialized));
    
    assert_eq!(serialized, expected, "H generator serialization mismatch!");
}
