use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    rc::Rc,
};

use eyre::{eyre, Context as _, OptionExt};

use frost_core::Ciphersuite;
use frost_ed25519::Ed25519Sha512;
use frost_secp256k1_tr::Secp256K1Sha256TR;
use bitcoin::key::XOnlyPublicKey;
use crate::util::taproot::tweak_internal_key;
use reqwest::Url;
use zeroize::Zeroizing;

use super::{
    args::Command,
    config::{Config, Group, Participant},
};

use crate::dkg::{args, cli};
use crate::{api, dkg::cli::MaybeIntoEvenY};

pub async fn dkg(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Dkg { ciphersuite, .. } = (*args).clone() else {
        panic!("invalid Command");
    };

    if ciphersuite == "ed25519" {
        dkg_for_ciphersuite::<Ed25519Sha512>(args).await
    } else if ciphersuite == "redpallas" {
        dkg_for_ciphersuite::<reddsa::frost::redpallas::PallasBlake2b512>(args).await
    } else if ciphersuite == "secp256k1-tr" {
        dkg_for_ciphersuite::<Secp256K1Sha256TR>(args).await
    } else {
        Err(eyre!("unsupported ciphersuite").into())
    }
}

pub(crate) async fn dkg_for_ciphersuite<C: Ciphersuite + MaybeIntoEvenY + 'static>(
    args: &Command,
) -> Result<(), Box<dyn Error>> {
    let Command::Dkg {
        config: config_path,
        description,
        server_url,
        ciphersuite: _,
        threshold,
        participants,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let mut input = Box::new(std::io::stdin().lock());
    let mut output = std::io::stdout();

    let config = Config::read(config_path.clone())?;

    // Accept full URLs with scheme; if no scheme provided, default to HTTPS.
    let server_url_parsed = if server_url.contains("://") {
        Url::parse(&server_url).wrap_err("error parsing server-url")?
    } else {
        // Default to HTTPS when no scheme is provided
        Url::parse(&format!("https://{server_url}")).wrap_err("error parsing server-url")?
    };

    let comm_pubkey = config
        .communication_key
        .clone()
        .ok_or_eyre("user not initialized")?
        .pubkey
        .clone();

    let mut participants = participants
        .iter()
        .map(|s| Ok(api::PublicKey(hex::decode(s)?.to_vec())))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    // Add ourselves if not already in the list
    if !participants.is_empty() && !participants.contains(&comm_pubkey) {
        participants.push(comm_pubkey.clone());
    }

    let dkg_config = args::ProcessedArgs {
        cli: false,
        // Enter network mode; scheme is HTTPS by default
        http: true,
        ip: server_url_parsed
            .host_str()
            .ok_or_eyre("host missing in URL")?
            .to_owned(),
        port: server_url_parsed
            .port_or_known_default()
            .expect("always works for https"),
    // Use HTTPS unless the user explicitly provided http://
    use_https: server_url_parsed.scheme() != "http",
        comm_privkey: Some(
            config
                .communication_key
                .clone()
                .ok_or_eyre("user not initialized")?
                .privkey
                .clone(),
        ),
        comm_pubkey: Some(comm_pubkey),
        comm_participant_pubkey_getter: Some(Rc::new(move |participant_pubkey| {
            config
                .contact_by_pubkey(participant_pubkey)
                .map(|p| p.pubkey.clone())
                .ok()
        })),
        min_signers: threshold,
        max_signers: None,
        participants,
        identifier: None,
    };

    // Generate key shares
    let (key_package, public_key_package, pubkey_map) =
        cli::cli_for_processed_args::<C>(dkg_config, &mut input, &mut output).await?;
    let key_package = Zeroizing::new(key_package);

    // ---------------------------------------------------------------------
    // Taproot tweak: For FROST Option A, keep P in PublicKeyPackage (for FROST signing)
    // and store Q separately. This ensures consistent challenge computation with P.
    let mut internal_key_bytes = None;
    if C::ID == Secp256K1Sha256TR::ID {
        // The verifying key may serialize in compressed (33B), uncompressed (65B),
        // or x-only (32B) formats depending on the backend. Convert to x-only.
        let p_bytes = public_key_package.verifying_key().serialize()?; // P
        let p_xonly = match p_bytes.len() {
            32 => XOnlyPublicKey::from_slice(&p_bytes)
                .map_err(|e| eyre!("invalid x-only internal key: {e}"))?,
            33 => XOnlyPublicKey::from_slice(&p_bytes[1..])
                .map_err(|e| eyre!("invalid compressed internal key (x-only): {e}"))?,
            65 => XOnlyPublicKey::from_slice(&p_bytes[1..33])
                .map_err(|e| eyre!("invalid uncompressed internal key (x-only): {e}"))?,
            l => return Err(eyre!("unexpected verifying key length: {l}").into()),
        };
        let (q_key, _t) = tweak_internal_key(p_xonly);

        // For Option A: Keep P in PublicKeyPackage, store Q in group ID for UI.
        // Both coordinator and participants will use P for FROST challenge computation.
        // The group ID (used for UI) will show Q for user recognition.
        internal_key_bytes = Some(p_xonly.serialize().to_vec());

        eprintln!("Taproot DKG: storing P in PublicKeyPackage for FROST signing");
        eprintln!("  Internal key (P): {}", hex::encode(p_xonly.serialize()));
        eprintln!("  Tweaked key (Q):  {}", hex::encode(q_key.serialize()));
        eprintln!("  Group ID will use Q for identification");

        // public_key_package remains with P (no modification needed)
        // Q will be used as the group identifier instead
    }

    // Reverse pubkey_map
    let pubkey_map = pubkey_map
        .into_iter()
        .map(|(k, v)| (v, k))
        .collect::<HashMap<_, _>>();

    // Create participants map
    let mut participants = BTreeMap::new();
    for identifier in public_key_package.verifying_shares().keys() {
        let pubkey = pubkey_map.get(identifier).ok_or_eyre("missing pubkey")?;
        let participant = Participant {
            identifier: identifier.serialize(),
            pubkey: pubkey.clone(),
        };
        participants.insert(hex::encode(identifier.serialize()), participant);
    }

    let group = Group {
        ciphersuite: C::ID.to_string(),
        description: description.clone(),
        key_package: postcard::to_allocvec(&key_package)?,
        public_key_package: postcard::to_allocvec(&public_key_package)?,
        internal_key: internal_key_bytes.clone(),
        participant: participants.clone(),
        server_url: Some(server_url.clone()),
    };
    // Re-read the config because the old instance is tied to the
    // `comm_participant_pubkey_getter` callback.
    // TODO: is this an issue?
    let mut config = Config::read(config_path)?;

    // Group ID: use Q for Taproot (for user recognition), P for other ciphersuites
    let group_id = if C::ID == Secp256K1Sha256TR::ID {
        // For Taproot, use Q (tweaked key) as group ID for user recognition
        let p_bytes = public_key_package.verifying_key().serialize()?;
        let p_xonly = XOnlyPublicKey::from_slice(&p_bytes[1..])?; // Skip 0x02 prefix
        let (q_key, _t) = tweak_internal_key(p_xonly);

        // Build compressed SEC1 encoding for Q as group ID
        let mut q_sec1 = vec![0x02u8];
        q_sec1.extend_from_slice(&q_key.serialize());
        hex::encode(q_sec1)
    } else {
        // For non-Taproot, use the public key as-is
        hex::encode(public_key_package.verifying_key().serialize()?)
    };

    config.group.insert(group_id, group);
    config.write()?;

    eprintln!(
        "Group created; information written to {}",
        config.path().expect("should not be None").display()
    );

    Ok(())
}
