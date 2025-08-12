use std::io::{BufRead, Write};

// No generic RandomizedCiphersuite needed here; Taproot path is monomorphic.
use frost_secp256k1_tr::Secp256K1Sha256TR;

use super::args::{Args, ProcessedArgs};
use super::comms::{cli::CLIComms, http::HTTPComms, socket::SocketComms, Comms};
use super::round_1::get_commitments;
use super::round_2_tr::send_signing_package_and_get_signature_shares_tr;
use super::cli::build_signing_package; // reuse generic builder (keeps logging)

/// Taproot-specific CLI path using aggregate_with_tweak (Option A).
pub async fn taproot_cli(
    args: &Args,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let pargs = ProcessedArgs::<Secp256K1Sha256TR>::new(args, reader, logger)?;
    eprintln!("Taproot Option A: verifying shares under P, aggregating with tweak to Q (key-path)");

    let mut comms: Box<dyn Comms<Secp256K1Sha256TR>> = if pargs.cli { Box::new(CLIComms::new()) } else if pargs.http { Box::new(HTTPComms::new(&pargs)?) } else { Box::new(SocketComms::new(&pargs)) };

    let participants_config = match get_commitments(&pargs, &mut *comms, reader, logger).await {
        Ok(p) => p,
        Err(e) => { let _ = comms.cleanup_on_error().await; return Err(e); }
    };

    // Ensure internal key present (cli.rs previously ensured). If missing, derive P from package.
    let mut pargs_mut = pargs.clone();
    if pargs_mut.internal_key.is_none() {
        let vk_bytes = participants_config.pub_key_package.verifying_key().serialize()?;
        if vk_bytes.len() == 33 && vk_bytes[0] == 0x02 { pargs_mut.internal_key = Some(vk_bytes[1..].to_vec()); }
    }

    let signing_package = build_signing_package(&pargs_mut, logger, participants_config.commitments.clone());

    let r = send_signing_package_and_get_signature_shares_tr(
        &pargs_mut,
        &mut *comms,
        reader,
        logger,
        participants_config,
        &signing_package,
    ).await;

    if let Err(e) = r { let _ = comms.cleanup_on_error().await; return Err(e); }
    Ok(())
}
