//! Helpers for Taproot tweaking (BIP‑341) – stable on bitcoin‑rs 0.32+

use bitcoin::{
    key::XOnlyPublicKey,
    secp256k1::{Scalar, Secp256k1},
    taproot::{TapTweakHash},
    hashes::Hash as _,
};

/// Compute the Taproot tweak `t` and the tweaked key `Q = P + t·G`.
///
/// * `internal` – the untweaked key **P** (a BIP‑340 x‑only key)
///
/// Returns **(Q, t)** where
/// * **Q** is the x‑only tweaked key that actually appears in the output
/// * **t** is the scalar tweak (mod *n*) that must be **added to every
///   signer’s secret‑key share** before a key‑path signature is valid.
pub fn tweak_internal_key(
    internal: XOnlyPublicKey,
) -> (XOnlyPublicKey, Scalar) {
    // H_TapTweak(Px || merkle_root) ; we never supply a merkle_root here
    let tweak_hash = TapTweakHash::from_key_and_tweak(internal, None);

    // convert 32‑byte hash → Scalar (mod n)
    let tweak_scalar = Scalar::from_be_bytes(tweak_hash.to_byte_array())
        .expect("hash is a valid scalar");

    // add tweak to the public key
    let secp = Secp256k1::verification_only();
    let (q_key, _parity) = internal
        .add_tweak(&secp, &tweak_scalar)
        .expect("tweak always succeeds");

    (q_key, tweak_scalar)
}
