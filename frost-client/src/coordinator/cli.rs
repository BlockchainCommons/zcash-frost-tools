use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use eyre::eyre;
use eyre::Context;

use crate::util::taproot::tweak_internal_key;
use bitcoin::{
    hashes::{sha256, Hash},
    key::XOnlyPublicKey,
    secp256k1::Scalar as SecScalar,
};
use frost::{round1::SigningCommitments, Identifier, SigningPackage};
use frost_core::{self as frost, Ciphersuite};
use frost_rerandomized::RandomizedCiphersuite;
use frost_secp256k1_tr::Secp256K1Sha256TR;
use k256::elliptic_curve::{bigint::U256, ops::Reduce};
use k256::{FieldBytes, Scalar};

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

    // ---------------------------------------------------------------------
    // Patch s = s + e·t after shares are combined (automatic for secp256k1-tr)
    if C::ID == Secp256K1Sha256TR::ID && !pargs.signature.is_empty() {
        // fetch P or fail with a plain String so `?` coerces into `Box<dyn Error>`
        let p_bytes = pargs
            .internal_key
            .clone()
            .ok_or::<Box<dyn std::error::Error>>(
                "internal_key missing; run DKG with secp256k1-tr ciphersuite".into(),
            )?;
        let p_xonly = XOnlyPublicKey::from_slice(&p_bytes).unwrap();
        let (q_key, tweak_scalar) = tweak_internal_key(p_xonly);

        // we signed exactly one message
        let msg = &pargs.messages[0];

        // read raw sig
        let mut sig =
            std::fs::read(&pargs.signature).wrap_err("cannot read signature file for tweaking")?;
        if sig.len() != 64 {
            return Err(eyre!("signature length is not 64 bytes").into());
        }

        // e = H(Rx ‖ Qx ‖ m)
        let r_x = &sig[..32];
        let e_scalar_secp = SecScalar::from_be_bytes(
            sha256::Hash::hash(&[r_x, &q_key.serialize(), msg].concat()).to_byte_array(),
        )
        .unwrap();

        // Convert raw big-endian bytes into k256 scalars **with modular reduction**
        let s_orig = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&sig[32..]));
        let t_k = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(
            &tweak_scalar.to_be_bytes(),
        ));
        let e_k = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(
            &e_scalar_secp.to_be_bytes(),
        ));

        // new_s = s + t·e  (mod n)
        let new_s = s_orig + t_k * e_k;
        sig[32..].copy_from_slice(new_s.to_bytes().as_slice());

        std::fs::write(&pargs.signature, &sig)?;
        eprintln!("Taproot tweak applied to {}", pargs.signature);
    }

    Ok(())
}

pub fn build_signing_package<C: Ciphersuite>(
    args: &ProcessedArgs<C>,
    logger: &mut dyn Write,
    commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
) -> SigningPackage<C> {
    let signing_package = SigningPackage::new(commitments, &args.messages[0]);
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
