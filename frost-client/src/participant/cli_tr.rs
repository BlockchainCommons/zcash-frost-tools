//! Taproot-specific participant signing (Option A: sign under P).
//!
//! With DKG fixed to store P in PublicKeyPackage, participants naturally
//! use P for challenge computation, matching coordinator expectations.

use std::io::{BufRead, Write};

use frost_secp256k1_tr::Secp256K1Sha256TR;
use frost_core::{
    keys::KeyPackage,
    round1::SigningNonces,
    round2::SignatureShare,
};

use super::{
    args::{Args, ProcessedArgs},
    comms::{cli::CLIComms, http::HTTPComms, socket::SocketComms, Comms},
    round1::{generate_nonces_and_commitments, print_values},
    round2::{print_values_round_2, round_2_request_inputs},
};
use crate::api::SendSigningPackageArgs;
use rand::thread_rng;
use zeroize::Zeroizing;

/// Taproot-specific participant CLI path using P for challenge computation.
pub async fn taproot_participant_cli(
    args: &Args,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let pargs = ProcessedArgs::<Secp256K1Sha256TR>::new(args, reader, logger)?;
    taproot_participant_cli_for_processed_args(pargs, reader, logger).await
}

pub async fn taproot_participant_cli_for_processed_args(
    pargs: ProcessedArgs<Secp256K1Sha256TR>,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut comms: Box<dyn Comms<Secp256K1Sha256TR>> = if pargs.cli {
        Box::new(CLIComms::new())
    } else if pargs.http {
        Box::new(HTTPComms::new(&pargs)?)
    } else {
        Box::new(SocketComms::new(&pargs))
    };

    eprintln!("Taproot participant: computing challenge with Q via sign_with_tweak (no rerandomization)");

    // Round 1 - same as generic path
    let key_package = &pargs.key_package;
    let mut rng = thread_rng();
    let (nonces, commitments) = generate_nonces_and_commitments(key_package, &mut rng);
    let nonces = Zeroizing::new(nonces);

    if pargs.cli {
        print_values(commitments, logger)?;
    }

    // Round 2 - Use standard FROST (no rerandomization) for secp256k1-tr
    let round_2_config = round_2_request_inputs(
        &mut *comms,
        input,
        logger,
        commitments,
        *key_package.identifier(),
        false, // standard FROST for secp256k1-tr (not rerandomized)
    )
    .await?;

    comms
        .confirm_message(input, logger, &round_2_config)
        .await?;

    // Use Taproot-specific signature generation with sign_with_tweak
    let signature = generate_signature_with_tweak(round_2_config, key_package, &nonces)?;

    comms
        .send_signature_share(*key_package.identifier(), signature)
        .await?;

    if pargs.cli {
        print_values_round_2(signature, logger)?;
    }
    writeln!(logger, "Done")?;

    Ok(())
}

/// Generate signature share using Taproot tweak for correct challenge computation.
pub fn generate_signature_with_tweak(
    config: SendSigningPackageArgs<Secp256K1Sha256TR>,
    key_package: &KeyPackage<Secp256K1Sha256TR>,
    signing_nonces: &SigningNonces<Secp256K1Sha256TR>,
) -> Result<SignatureShare<Secp256K1Sha256TR>, frost_core::Error<Secp256K1Sha256TR>> {
    let signing_package = config.signing_package.first().unwrap();

    // Use Taproot-specific signing with tweak to compute challenge with Q
    // This matches what aggregate_with_tweak expects from participants
    let merkle_root: Option<&[u8]> = None; // key-path signing (no script)

    frost_secp256k1_tr::round2::sign_with_tweak(
        signing_package,
        signing_nonces,
        key_package,
        merkle_root,
    )
}
