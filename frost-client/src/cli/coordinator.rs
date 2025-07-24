use std::collections::HashMap;
use std::error::Error;

use eyre::eyre;
use eyre::Context;
use eyre::OptionExt;

use crate::cipher::PublicKey;
use frost_core::keys::PublicKeyPackage;
use frost_core::Ciphersuite;
use frost_ed25519::Ed25519Sha512;
use frost_rerandomized::RandomizedCiphersuite;
use frost_secp256k1_tr::Secp256K1Sha256TR;
use bitcoin::{
    hashes::{sha256, Hash},
    key::XOnlyPublicKey,
    secp256k1::Scalar as SecScalar,
};
use k256::{Scalar, FieldBytes};
use k256::elliptic_curve::{
    bigint::U256,
    ops::Reduce,
};
use crate::util::taproot::tweak_internal_key;
use reddsa::frost::redpallas::PallasBlake2b512;
use reqwest::Url;

use crate::coordinator::args;
use crate::coordinator::cli;

use super::args::Command;
use super::config::Config;

pub async fn run(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Coordinator { config, group, .. } = (*args).clone() else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let group = config.group.get(&group).ok_or_eyre("Group not found")?;

    if group.ciphersuite == Ed25519Sha512::ID {
        run_for_ciphersuite::<Ed25519Sha512>(args).await
    } else if group.ciphersuite == PallasBlake2b512::ID {
        run_for_ciphersuite::<PallasBlake2b512>(args).await
    } else if group.ciphersuite == Secp256K1Sha256TR::ID {
        run_for_ciphersuite::<Secp256K1Sha256TR>(args).await
    } else {
        Err(eyre!("unsupported ciphersuite").into())
    }
}

pub(crate) async fn run_for_ciphersuite<C: RandomizedCiphersuite + 'static>(
    args: &Command,
) -> Result<(), Box<dyn Error>> {
    let Command::Coordinator {
        config,
        server_url,
        group,
        signers,
        message,
        randomizer,
        signature,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let group = config.group.get(&group).ok_or_eyre("Group not found")?;

    let public_key_package: PublicKeyPackage<C> = postcard::from_bytes(&group.public_key_package)?;

    let mut input = Box::new(std::io::stdin().lock());
    let mut output = std::io::stdout();

    let server_url = if let Some(server_url) = server_url {
        server_url
    } else {
        group.server_url.clone().ok_or_eyre("server-url required")?
    };
    let server_url_parsed =
        Url::parse(&format!("https://{server_url}")).wrap_err("error parsing server-url")?;

    let signers = signers
        .iter()
        .map(|s| {
            let pubkey = PublicKey(hex::decode(s)?.to_vec());
            let contact = group.participant_by_pubkey(&pubkey)?;
            Ok((pubkey, contact.identifier()?))
        })
        .collect::<Result<HashMap<_, _>, Box<dyn Error>>>()?;
    let num_signers = signers.len() as u16;

    let messages_vec =
        args::read_messages(&message, &mut output, &mut input)?;

    let pargs = args::ProcessedArgs {
        cli: false,
        http: true,
        signers,
        num_signers,
        public_key_package,
        messages: messages_vec.clone(),
        randomizers: args::read_randomizers(&randomizer, &mut output, &mut input)?,
        signature: signature.clone(),
        ip: server_url_parsed
            .host_str()
            .ok_or_eyre("host missing in URL")?
            .to_owned(),
        port: server_url_parsed
            .port_or_known_default()
            .expect("always works for https"),
        comm_privkey: Some(
            config
                .communication_key
                .clone()
                .ok_or_eyre("user not initialized")?
                .privkey
                .clone(),
        ),
        comm_pubkey: Some(
            config
                .communication_key
                .ok_or_eyre("user not initialized")?
                .pubkey
                .clone(),
        ),
        internal_key: group.internal_key.clone(),
    };

    cli::cli_for_processed_args(pargs, &mut input, &mut output).await?;

    // ---------------------------------------------------------------------
    // Patch s = s + e·t  after shares are combined (automatic for secp256k1-tr)
    if C::ID == Secp256K1Sha256TR::ID && !signature.is_empty() {
    // fetch P or fail with a plain String so `?` coerces into `Box<dyn Error>`
    let p_bytes = group
        .internal_key
        .clone()
        .ok_or::<Box<dyn std::error::Error>>("internal_key missing; run DKG with secp256k1-tr ciphersuite".into())?;
        let p_xonly = XOnlyPublicKey::from_slice(&p_bytes).unwrap();
        let (q_key, tweak_scalar) = tweak_internal_key(p_xonly);

        // we signed exactly one message
        let msg = &messages_vec[0];

        // read raw sig
        let mut sig = std::fs::read(&signature)
            .wrap_err("cannot read signature file for tweaking")?;
        if sig.len() != 64 {
            return Err(eyre!("signature length is not 64 bytes").into());
        }

        // e = H(Rx ‖ Qx ‖ m)
        let r_x = &sig[..32];
        let e_scalar_secp = SecScalar::from_be_bytes(
            sha256::Hash::hash(&[r_x, &q_key.serialize(), msg].concat()).to_byte_array(),
        )
        .unwrap();

        // Convert raw big‑endian bytes into k256 scalars **with modular reduction**
        let s_orig  =
            <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&sig[32..]));
        let t_k =
            <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&tweak_scalar.to_be_bytes()));
        let e_k =
            <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&e_scalar_secp.to_be_bytes()));

        // new_s = s + t·e  (mod n)
        let new_s = s_orig + t_k * e_k;
        sig[32..].copy_from_slice(new_s.to_bytes().as_slice());

        std::fs::write(&signature, &sig)?;
        eprintln!("Taproot tweak applied to {}", signature);
    }

    Ok(())
}
