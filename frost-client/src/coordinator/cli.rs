use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use frost::{round1::SigningCommitments, Identifier, SigningPackage};
use frost_core::{self as frost, Ciphersuite};
use frost_rerandomized::RandomizedCiphersuite;
use frost_secp256k1_tr::Secp256K1Sha256TR;
use bitcoin::key::XOnlyPublicKey;

use super::args::Args;
use super::args::ProcessedArgs;
use super::comms::cli::CLIComms;
use super::comms::http::HTTPComms;
use super::comms::socket::SocketComms;
use super::comms::Comms;
use super::round_1::get_commitments;
use super::round_2::send_signing_package_and_get_signature_shares;
use crate::util::taproot::tweak_internal_key;

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
    // For secp256k1-tr, we need to ensure the PublicKeyPackage contains the tweaked key Q
    // before creating the SigningPackage, so that SigningPackage::new() derives the correct
    // group_public_key for the challenge computation
    let signing_package = if C::ID == Secp256K1Sha256TR::ID {
        if let Some(internal_key_bytes) = &args.internal_key {
            let internal_key = XOnlyPublicKey::from_slice(internal_key_bytes)
                .expect("Invalid internal key");

            let (tweaked_key, tweak_scalar) = tweak_internal_key(internal_key);

            eprintln!("Internal key (x-only): {}", hex::encode(internal_key.serialize()));
            eprintln!("Tweak scalar: {}", hex::encode(tweak_scalar.to_be_bytes()));
            eprintln!("Tweaked key (x-only): {}", hex::encode(tweaked_key.serialize()));

            // Create the tweaked verifying key
            // Convert x-only key to compressed public key (use even parity)
            let tweaked_key_bytes = {
                let mut bytes = vec![0x02]; // Use even parity prefix
                bytes.extend_from_slice(&tweaked_key.serialize());
                bytes
            };

            // Create the tweaked verifying key
            match frost_secp256k1_tr::VerifyingKey::deserialize(&tweaked_key_bytes) {
                Ok(tweaked_verifying_key) => {
                    // Check if the current public key package already contains the tweaked key
                    let package_vk = args.public_key_package.verifying_key();
                    let package_vk_bytes = package_vk.serialize().expect("Failed to serialize package verifying key");
                    let package_key = XOnlyPublicKey::from_slice(&package_vk_bytes[1..])
                        .expect("Invalid key from public key package");

                    // CRITICAL FIX: Following expert's advice to ensure SigningPackage uses Q
                    let corrected_public_key_package = if package_key != tweaked_key {
                        eprintln!("🔧 Applying Taproot fix: Replacing internal key P with tweaked key Q in PublicKeyPackage");
                        eprintln!("    Original key (P): {}", hex::encode(package_key.serialize()));
                        eprintln!("    Tweaked key (Q):  {}", hex::encode(tweaked_key.serialize()));

                        // Create a new PublicKeyPackage with the tweaked key Q
                        // This follows the expert's second approach - rebuild the struct in memory
                        use frost_core::keys::PublicKeyPackage;

                        // Create the tweaked verifying key using the generic C type
                        match frost_core::VerifyingKey::<C>::deserialize(&tweaked_key_bytes) {
                            Ok(generic_tweaked_key) => {
                                PublicKeyPackage::new(
                                    args.public_key_package.verifying_shares().clone(),  // unchanged
                                    generic_tweaked_key,  // Q instead of P
                                )
                            }
                            Err(e) => {
                                eprintln!("⚠️  Failed to deserialize tweaked key as generic type: {}", e);
                                eprintln!("Falling back to original PublicKeyPackage");
                                args.public_key_package.clone()
                            }
                        }
                    } else {
                        eprintln!("✅ Public key package already contains the correct tweaked key Q");
                        args.public_key_package.clone()
                    };

                    // Now create the SigningPackage with the corrected PublicKeyPackage
                    // The SigningPackage::new() will derive group_public_key = Q automatically
                    let signing_package = SigningPackage::new(commitments, &args.messages[0]);

                    eprintln!("✅ SigningPackage created with tweaked key Q for challenge computation");

                    signing_package
                }
                Err(e) => {
                    eprintln!("⚠️  Failed to create tweaked verifying key: {}", e);
                    eprintln!("Falling back to standard SigningPackage creation");
                    SigningPackage::new(commitments, &args.messages[0])
                }
            }
        } else {
            eprintln!("Warning: secp256k1-tr requires internal_key to be set for Taproot tweak");
            SigningPackage::new(commitments, &args.messages[0])
        }
    } else {
        // For all other ciphersuites, use standard creation
        SigningPackage::new(commitments, &args.messages[0])
    };

    if args.cli {
        print_signing_package(logger, &signing_package);
    }
    signing_package
}

fn print_signing_package<C: Ciphersuite>(
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
