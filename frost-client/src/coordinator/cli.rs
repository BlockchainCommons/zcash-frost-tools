use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use frost::{round1::SigningCommitments, Identifier, SigningPackage};
use frost_core::{self as frost, Ciphersuite};
use frost_rerandomized::RandomizedCiphersuite;
use frost_secp256k1_tr::Secp256K1Sha256TR;

use super::args::Args;
use super::args::ProcessedArgs;
use super::comms::cli::CLIComms;
use super::comms::http::HTTPComms;
use super::comms::socket::SocketComms;
use super::comms::Comms;
use super::round_1::get_commitments;
use super::round_2::send_signing_package_and_get_signature_shares;

pub async fn cli<C: RandomizedCiphersuite + 'static>(
    args: &Args,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let pargs = ProcessedArgs::<C>::new(args, reader, logger)?;
    cli_for_processed_args(pargs, reader, logger).await
}

pub async fn cli_for_processed_args<C: RandomizedCiphersuite + 'static>(
    pargs: ProcessedArgs<C>,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut comms: Box<dyn Comms<C>> = if pargs.cli {
        Box::new(CLIComms::new())
    } else if pargs.http {
        Box::new(HTTPComms::new(&pargs)?)
    } else {
        Box::new(SocketComms::new(&pargs))
    };

    if !pargs.randomizers.is_empty() && pargs.randomizers.len() != pargs.messages.len() {
        return Err("Number of randomizers must match number of messages".into());
    }

    let r = get_commitments(&pargs, &mut *comms, reader, logger).await;
    let Ok(mut participants_config) = r else {
        let _ = comms.cleanup_on_error().await;
        return Err(r.unwrap_err());
    };

    // For secp256k1-tr, replace the PublicKeyPackage with one containing the tweaked key Q
    // This ensures that signing operations use Q for challenge computation
    if C::ID == Secp256K1Sha256TR::ID {
        if let Some(internal_key_bytes) = &pargs.internal_key {
            if let Ok(internal_key) = bitcoin::secp256k1::XOnlyPublicKey::from_slice(internal_key_bytes) {
                let (tweaked_key, _tweak_scalar) = crate::util::taproot::tweak_internal_key(internal_key);

                // Create tweaked verifying key
                let tweaked_key_bytes = {
                    let mut bytes = vec![0x02]; // Use even parity prefix
                    bytes.extend_from_slice(&tweaked_key.serialize());
                    bytes
                };

                if let Ok(tweaked_verifying_key) = frost_core::VerifyingKey::<C>::deserialize(&tweaked_key_bytes) {
                    // Replace the PublicKeyPackage with one containing Q
                    use frost_core::keys::PublicKeyPackage;
                    participants_config.pub_key_package = PublicKeyPackage::new(
                        participants_config.pub_key_package.verifying_shares().clone(),  // Keep original shares
                        tweaked_verifying_key,  // Use Q instead of P
                    );

                    eprintln!("✅ Updated ParticipantsConfig.pub_key_package: P → Q for Taproot signing");
                    eprintln!("    Internal key (P): {}", hex::encode(internal_key.serialize()));
                    eprintln!("    Tweaked key (Q):  {}", hex::encode(tweaked_key.serialize()));
                } else {
                    eprintln!("⚠️  Failed to create tweaked verifying key for ParticipantsConfig");
                }
            }
        }
    }

    let signing_package =
        build_signing_package(&pargs, logger, participants_config.commitments.clone());

    let r = send_signing_package_and_get_signature_shares(
        &pargs,
        &mut *comms,
        reader,
        logger,
        participants_config,
        &signing_package,
    )
    .await;

    if let Err(e) = r {
        let _ = comms.cleanup_on_error().await;
        return Err(e);
    }

    Ok(())
}

pub fn build_signing_package<C: Ciphersuite>(
    args: &ProcessedArgs<C>,
    logger: &mut dyn Write,
    commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
) -> SigningPackage<C> {
    // Create the SigningPackage with the provided commitments
    // Note: For secp256k1-tr, the ParticipantsConfig.pub_key_package has already been
    // updated to contain the tweaked key Q in the main coordinator flow
    let signing_package = SigningPackage::new(commitments, &args.messages[0]);

    if args.cli {
        print_signing_package(logger, &signing_package);
    }
    signing_package
}fn print_signing_package<C: Ciphersuite>(
    logger: &mut dyn Write,
    signing_package: &SigningPackage<C>,
) {
    writeln!(
        logger,
        "Signing Package:\n{}",
        serde_json::to_string(&signing_package).unwrap()
    )
    .unwrap();
}
