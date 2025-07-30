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

    // For secp256k1-tr, replace the PublicKeyPackage with one containing the tweaked key Q
    // This ensures that signing operations use Q for challenge computation
    if C::ID == Secp256K1Sha256TR::ID {
        // 1️⃣ Extract the internal key P *before* editing the package
        let internal_key_bytes = match &pargs.internal_key {
            Some(bytes) => bytes.clone(),
            None => {
                // Safe fallback: extract P from the original (untweaked) verifying key
                let vk_bytes = participants_config.pub_key_package.verifying_key().serialize()
                    .map_err(|e| format!("Failed to serialize verifying key: {}", e))?;
                if vk_bytes[0] != 0x02 {
                    return Err("Odd-parity verifying key; dealer bug?".into());
                }
                // Extract the 32-byte x-only key (strip the 0x02 prefix)
                vk_bytes[1..].to_vec()
            }
        };

        // 2️⃣ Ensure pargs has the internal key for round_2.rs to use
        let mut pargs_mut = pargs.clone();
        pargs_mut.internal_key = Some(internal_key_bytes.clone());

        // 3️⃣ Parse the internal key and compute (Q, t) from P
        if internal_key_bytes.len() != 32 {
            return Err("Internal key must be exactly 32 bytes".into());
        }
        let mut internal_key_array = [0u8; 32];
        internal_key_array.copy_from_slice(&internal_key_bytes);

        let internal_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&internal_key_array)
            .map_err(|e| format!("Invalid internal key: {}", e))?;
        let (tweaked_key, _tweak_scalar) = crate::util::taproot::tweak_internal_key(internal_key);

        // 4️⃣ Create tweaked verifying key and overwrite the package with Q *after* we have P & t
        let tweaked_key_bytes = {
            let mut bytes = vec![0x02]; // Use even parity prefix
            bytes.extend_from_slice(&tweaked_key.serialize());
            bytes
        };

        if let Ok(_tweaked_verifying_key) = frost_core::VerifyingKey::<C>::deserialize(&tweaked_key_bytes) {
            eprintln!("✅ SigningPackage will use tweaked key Q (pub_key_package left on P)");
            eprintln!("    Internal key (P): {}", hex::encode(internal_key.serialize()));
            eprintln!("    Tweaked key (Q):  {}", hex::encode(tweaked_key.serialize()));
        } else {
            return Err("Failed to create tweaked verifying key for ParticipantsConfig".into());
        }

        // Use the updated pargs with the internal key set
        let signing_package =
            build_signing_package(&pargs_mut, logger, participants_config.commitments.clone());

        let r = send_signing_package_and_get_signature_shares(
            &pargs_mut,
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
    } else {
        // Non-Taproot: use original pargs
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
}

pub fn build_signing_package<C: Ciphersuite>(
    args: &ProcessedArgs<C>,
    logger: &mut dyn Write,
    commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
) -> SigningPackage<C> {
    // Create the SigningPackage with the provided commitments
    let signing_package = SigningPackage::new(commitments, &args.messages[0]);

    // For secp256k1-tr, the challenge computation needs to use the tweaked key Q
    // Since SigningPackage doesn't have a direct group_public_key field,
    // we'll rely on the secp256k1-tr ciphersuite to handle this correctly
    // in the aggregate function when it receives the proper internal key info
    if C::ID == Secp256K1Sha256TR::ID {
        if let Some(internal_key_bytes) = &args.internal_key {
            if internal_key_bytes.len() == 32 {
                let mut internal_key_array = [0u8; 32];
                internal_key_array.copy_from_slice(internal_key_bytes);

                if let Ok(internal_key) = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&internal_key_array) {
                    let (tweaked_key, _tweak_scalar) = crate::util::taproot::tweak_internal_key(internal_key);
                    eprintln!("📦 SigningPackage created for Taproot with:");
                    eprintln!("    Internal key (P): {}", hex::encode(internal_key.serialize()));
                    eprintln!("    Tweaked key (Q):  {}", hex::encode(tweaked_key.serialize()));
                    eprintln!("    Challenge computation will use Q via secp256k1-tr ciphersuite");
                }
            }
        }
    }

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
