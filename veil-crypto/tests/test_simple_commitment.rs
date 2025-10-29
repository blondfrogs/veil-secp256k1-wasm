use veil_crypto::pedersen::pedersen_ecmult_point;
use veil_crypto::pedersen::get_generator_h_point;
use k256::{Scalar, elliptic_curve::{PrimeField, sec1::ToEncodedPoint}};

#[test]
fn test_simple_commitment() {
    // Compute: 1 * G + 1 * H
    let one_scalar = Scalar::ONE;
    let h_point = get_generator_h_point().unwrap();

    let commitment = pedersen_ecmult_point(&one_scalar, 1, &h_point).unwrap();
    let commitment_affine = commitment.to_affine();

    let serialized = commitment_affine.to_encoded_point(true);
    let bytes = serialized.as_bytes();

    println!("1*G + 1*H = {}", hex::encode(bytes));
    println!("  First byte (parity): {:#04x}", bytes[0]);
}

#[test]
fn test_300_commitment() {
    // Compute: sec[0] * G + 300 * H
    // Using exact sec[0] from our test
    let sec0_bytes = hex::decode("064bb5f8fc7e1ba1df9308520a7e26d7b3bd5d418928272cd2c1ae0e9c026fdc").unwrap();
    let mut sec0_array = [0u8; 32];
    sec0_array.copy_from_slice(&sec0_bytes);

    let sec0_scalar = Scalar::from_repr(sec0_array.into()).unwrap();
    let h_point = get_generator_h_point().unwrap();

    let commitment = pedersen_ecmult_point(&sec0_scalar, 300, &h_point).unwrap();
    let commitment_affine = commitment.to_affine();

    let serialized = commitment_affine.to_encoded_point(true);
    let bytes = serialized.as_bytes();

    println!("sec[0]*G + 300*H = {}", hex::encode(bytes));
    println!("  First byte (parity): {:#04x}", bytes[0]);
    println!("  Expected parity: 0x02 (even y) based on C test vector");
    println!("  Match: {}", bytes[0] == 0x02);
}
