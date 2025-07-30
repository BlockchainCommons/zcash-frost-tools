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
    let Ok(participants_config) = r else {
        let _ = comms.cleanup_on_error().await;
        return Err(r.unwrap_err());
    };

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
    // For secp256k1-tr, verify we have the internal key for Taproot operations
    if C::ID == Secp256K1Sha256TR::ID {
        if let Some(internal_key_bytes) = &args.internal_key {
            // Verify the internal key is valid
            if let Ok(internal_key) = bitcoin::secp256k1::XOnlyPublicKey::from_slice(internal_key_bytes) {
                // Compute the expected tweaked key Q = P + H_TapTweak(P || 0) * G
                let (tweaked_key, _tweak_scalar) = crate::util::taproot::tweak_internal_key(internal_key);
                
                // Check what key is in the public key package
                let package_vk = args.public_key_package.verifying_key();
                let package_vk_bytes = package_vk.serialize().expect("Failed to serialize package verifying key");
                let package_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&package_vk_bytes[1..])
                    .expect("Invalid key from public key package");
                
                if package_key == internal_key {
                    eprintln!("✅ Public key package contains internal key P (correct for Taproot)");
                } else if package_key == tweaked_key {
                    eprintln!("ℹ️  Public key package contains tweaked key Q");
                    eprintln!("    Internal key (P): {}", hex::encode(internal_key.serialize()));
                    eprintln!("    Package key (Q):  {}", hex::encode(package_key.serialize()));
                } else {
                    eprintln!("⚠️  Warning: Public key package key doesn't match internal key or expected tweaked key");
                    eprintln!("    Internal key (P): {}", hex::encode(internal_key.serialize()));
                    eprintln!("    Package key:      {}", hex::encode(package_key.serialize()));
                    eprintln!("    Expected Q:       {}", hex::encode(tweaked_key.serialize()));
                }
            } else {
                eprintln!("⚠️  Warning: Invalid internal key provided for secp256k1-tr");
            }
        } else {
            eprintln!("⚠️  Warning: secp256k1-tr requires --internal-key flag for Taproot operations");
        }
    }
    
    // Create standard SigningPackage - no hot-patching
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
