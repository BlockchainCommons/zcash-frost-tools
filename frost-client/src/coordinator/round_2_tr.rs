//! Taproot-specific Round 2 aggregation (Option A: sign under P, aggregate with tweak to Q).
//!
//! Participants sign using the untweaked PublicKeyPackage (P). The coordinator verifies
//! shares against P and applies the Taproot tweak only during aggregation via
//! `aggregate_with_tweak`, which computes the challenge with Q and adjusts `s`.

use std::io::{BufRead, Write};

use frost_core as frost;
use frost::{Signature, SigningPackage};
use frost_secp256k1_tr::Secp256K1Sha256TR;

use super::{args::ProcessedArgs, comms::Comms, round_1::ParticipantsConfig};
use crate::coordinator::round_2::print_signature; // reuse generic printer

/// Send SigningPackage, collect signature shares, aggregate with Taproot tweak.
pub async fn send_signing_package_and_get_signature_shares_tr(
    args: &ProcessedArgs<Secp256K1Sha256TR>,
    comms: &mut dyn Comms<Secp256K1Sha256TR>,
    input: &mut dyn BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig<Secp256K1Sha256TR>,
    signing_package: &SigningPackage<Secp256K1Sha256TR>,
) -> Result<Signature<Secp256K1Sha256TR>, Box<dyn std::error::Error>> {
    // No rerandomization / randomizer in Taproot Option A.
    let signatures_list = comms
        .send_signing_package_and_get_signature_shares(input, logger, signing_package, None)
        .await?;

    eprintln!("Taproot Option A: verifying shares under P, aggregating with tweak to Q (key‑path)");

    // Use fully qualified call to ensure we get the Taproot tweak aggregator
    let sig = frost_secp256k1_tr::aggregate_with_tweak(
        signing_package,
        &signatures_list,
        &participants.pub_key_package, // Now contains P
        None, // key-path (no merkle root)
    )?;

    // Debug assertion: verify signature validates under Q (tweaked) but not P (internal)
    #[cfg(debug_assertions)]
    {
        use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey, Message};
        use bitcoin::secp256k1::schnorr::Signature as SchnorrSig;

        let msg_bytes = signing_package.message();
        let msg = Message::from_digest_slice(msg_bytes).expect("Message should be 32 bytes");

        // Extract P from the PublicKeyPackage (32 bytes x-only)
        let p_bytes = participants.pub_key_package.verifying_key().serialize()
            .expect("Failed to serialize P");
        let px_bytes = &p_bytes[1..]; // Strip 0x02 prefix to get x-only
        let xp = XOnlyPublicKey::from_slice(px_bytes)
            .expect("Failed to parse P as x-only public key");

        // Compute Q by tweaking P
        let (xq, _parity) = crate::util::taproot::tweak_internal_key(xp);

        // Convert FROST signature to secp256k1 format
        let sig_bytes = sig.serialize().expect("Failed to serialize signature");
        let schnorr_sig = SchnorrSig::from_slice(&sig_bytes)
            .expect("Failed to parse FROST signature as Schnorr");

        let secp = Secp256k1::verification_only();

        // Signature should verify under Q (tweaked key)
        assert!(
            secp.verify_schnorr(&schnorr_sig, &msg, &xq).is_ok(),
            "Taproot signature must verify under Q (tweaked key)"
        );

        // Signature should NOT verify under P (internal key)
        assert!(
            secp.verify_schnorr(&schnorr_sig, &msg, &xp).is_err(),
            "Taproot signature must NOT verify under P (internal key)"
        );

        eprintln!("✓ Debug check: signature verifies under Q, not P (Taproot tweak applied correctly)");
    }

    print_signature(args, logger, sig.clone())?;
    Ok(sig)
}
