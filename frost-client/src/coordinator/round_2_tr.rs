//! Taproot-specific Round 2 aggregation (Option A: sign under P, aggregate with tweak to Q).
//!
//! Participants sign using the untweaked PublicKeyPackage (P). The coordinator verifies
//! shares against P and applies the Taproot tweak only during aggregation via
//! `aggregate_with_tweak`, which computes the challenge with Q and adjusts `s`.

use std::io::{BufRead, Write};

use frost_core as frost;
use frost::{Signature, SigningPackage};
use frost_secp256k1_tr::Secp256K1Sha256TR;
use frost_secp256k1_tr::aggregate_with_tweak;

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

    // With DKG fix, participants.pub_key_package now contains P, so we can use it directly.
    // Both coordinator and participants use P for FROST challenge computation.
    let sig = aggregate_with_tweak(
        signing_package,
        &signatures_list,
        &participants.pub_key_package, // Now contains P
        None, // key-path (no merkle root)
    )?;

    print_signature(args, logger, sig.clone())?;
    Ok(sig)
}
