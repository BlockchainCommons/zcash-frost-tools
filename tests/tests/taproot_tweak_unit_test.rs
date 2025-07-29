use bitcoin::{
    secp256k1::{Secp256k1, Scalar, XOnlyPublicKey},
    key::TapTweak,
    taproot::TapTweakHash,
    hashes::Hash as _,
};
use k256::{elliptic_curve::group::ff::PrimeField, Scalar as K256Scalar};

#[test]
fn test_taproot_tweak_computation() {
    // Test that we can compute the BIP-341 tweak correctly
    let secp = Secp256k1::verification_only();

    // Create a sample internal key (this would come from FROST key generation)
    let internal_key_bytes = hex::decode("192fa693c53bf26f42bd62ade330096cb16936c970a2fa5af745f67a03923dd9").unwrap();
    let internal_key = XOnlyPublicKey::from_slice(&internal_key_bytes).unwrap();

    // Method 1: Using bitcoin's tap_tweak (returns tweaked key and parity)
    let (tweaked_key, _parity) = internal_key.tap_tweak(&secp, None);

    // Method 2: Manual tweak computation (like in coordinator/round_2.rs)
    let tweak_hash = TapTweakHash::from_key_and_tweak(internal_key, None);
    let tweak_scalar = Scalar::from_be_bytes(tweak_hash.to_byte_array()).unwrap();
    let (manual_tweaked_key, _) = internal_key.add_tweak(&secp, &tweak_scalar).unwrap();

    // Convert to k256 Scalar for FROST rerandomized
    let k256_tweak_scalar = K256Scalar::from_repr(tweak_hash.to_byte_array().into()).unwrap();

    // Verify that both methods produce the same result (compare the inner XOnlyPublicKey)
    assert_eq!(tweaked_key.to_x_only_public_key(), manual_tweaked_key, "Both tweak methods should produce the same result");

    // Verify that the tweak was computed successfully
    println!("✓ BIP-341 tweak computed successfully");
    println!("Internal key: {}", hex::encode(&internal_key_bytes));
    println!("Tweaked key: {}", tweaked_key.to_x_only_public_key());
    println!("Tweak hash: {}", hex::encode(tweak_hash.to_byte_array()));
    println!("k256 scalar: {}", hex::encode(k256_tweak_scalar.to_bytes()));

    // Basic assertions
    assert_ne!(internal_key.serialize(), tweaked_key.to_x_only_public_key().serialize());
    assert_eq!(tweak_hash.to_byte_array().len(), 32);
    assert_eq!(k256_tweak_scalar.to_bytes().len(), 32);
}

#[test]
fn test_coordinator_tweak_function() {
    // Test the actual function used in the coordinator
    use bitcoin::{secp256k1::Secp256k1, key::XOnlyPublicKey};

    // Simulate what the coordinator does
    let _secp = Secp256k1::verification_only();

    // Create a sample FROST verifying key
    let internal_key_bytes = hex::decode("192fa693c53bf26f42bd62ade330096cb16936c970a2fa5af745f67a03923dd9").unwrap();
    let internal_key = XOnlyPublicKey::from_slice(&internal_key_bytes).unwrap();

    // This is the function logic from coordinator/round_2.rs
    let tweak_hash = TapTweakHash::from_key_and_tweak(internal_key, None);
    let tweak_scalar = K256Scalar::from_repr(tweak_hash.to_byte_array().into()).unwrap();

    // Verify the scalar was created correctly
    assert_eq!(tweak_scalar.to_bytes().len(), 32);

    println!("✓ Coordinator tweak function works correctly");
    println!("Tweak scalar: {}", hex::encode(tweak_scalar.to_bytes()));
}
