use std::{collections::BTreeMap, error::Error};

use eyre::{eyre, OptionExt};
use itertools::izip;
use rand::thread_rng;

use frost_core::{keys::KeyPackage, Ciphersuite};
use frost_ed25519::Ed25519Sha512;
use frost_secp256k1_tr::Secp256K1Sha256TR;
use bitcoin::key::XOnlyPublicKey;

use crate::util::taproot::tweak_internal_key;

use super::{
    args::Command,
    config::{Config, Group, Participant},
    contact::Contact,
};

use crate::trusted_dealer;
use crate::trusted_dealer::MaybeIntoEvenY;

pub fn trusted_dealer(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::TrustedDealer { ciphersuite, .. } = (*args).clone() else {
        panic!("invalid Command");
    };

    if ciphersuite == "ed25519" {
        trusted_dealer_for_ciphersuite::<Ed25519Sha512>(args)
    } else if ciphersuite == "redpallas" {
        trusted_dealer_for_ciphersuite::<reddsa::frost::redpallas::PallasBlake2b512>(args)
    } else if ciphersuite == "secp256k1-tr" {
        trusted_dealer_for_ciphersuite::<Secp256K1Sha256TR>(args)
    } else {
        Err(eyre!("unsupported ciphersuite").into())
    }
}

pub(crate) fn trusted_dealer_for_ciphersuite<C: Ciphersuite + MaybeIntoEvenY + 'static>(
    args: &Command,
) -> Result<(), Box<dyn Error>> {
    let Command::TrustedDealer {
        config,
        description,
        ciphersuite: _,
        threshold,
        num_signers,
        names,
        server_url,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    if config.len() != num_signers as usize {
        return Err(
            eyre!("The `config` option must specify `num_signers` different config files").into(),
        );
    }
    if names.len() != num_signers as usize {
        return Err(eyre!("The `names` option must specify `num_signers` names").into());
    }

    let trusted_dealer_config = trusted_dealer::Config {
        max_signers: num_signers,
        min_signers: threshold,
        secret: vec![],
    };
    let mut rng = thread_rng();

    // Generate key shares
    let (shares, mut public_key_package) =
        trusted_dealer::trusted_dealer::<C, _>(&trusted_dealer_config, &mut rng)?;

    // Always apply Taproot tweak for secp256k1-tr ciphersuite
    let mut internal_key_bytes = None;
    if C::ID == Secp256K1Sha256TR::ID {
        // (1) untweaked P
        let p_bytes = public_key_package.verifying_key().serialize()?;
        internal_key_bytes = Some(p_bytes.clone());
        let p_xonly = XOnlyPublicKey::from_slice(&p_bytes).expect("x-only key");
        // (2) tweak -> Q
        let (q_key, _t) = tweak_internal_key(p_xonly);
        // (3) build a fresh PublicKeyPackage with the tweaked key Q
        use frost_core::{keys::PublicKeyPackage, VerifyingKey};

        let q_vk = VerifyingKey::<C>::deserialize(&q_key.serialize())
            .map_err(|_| eyre!("cannot deserialize tweaked key"))?;

        public_key_package = PublicKeyPackage::new(
            public_key_package.verifying_shares().clone(), // getter from derive_getters
            q_vk,
        );
    }

    // First pass over configs; create participants map
    let mut participants = BTreeMap::new();
    let mut contacts = Vec::new();
    for (identifier, path, name) in izip!(shares.keys(), config.iter(), names.iter()) {
        let config = Config::read(Some(path.to_string()))?;
        let pubkey = config
            .communication_key
            .ok_or_eyre("config not initialized")?
            .pubkey
            .clone();
        let participant = Participant {
            identifier: identifier.serialize(),
            pubkey: pubkey.clone(),
        };
        participants.insert(hex::encode(identifier.serialize()), participant);
        let contact = Contact {
            version: None,
            name: name.clone(),
            pubkey,
        };
        contacts.push(contact);
    }

    // Second pass over configs; write group information
    for (share, path) in shares.values().zip(config.iter()) {
        let mut config = Config::read(Some(path.to_string()))?;
        // IMPORTANT: the TrustedDealer command is intended for tests only, see
        // comment in [`Command::TrustedDealer`]. If you're using this code as a
        // reference, note that participants should not convert a SecretShare
        // into a KeyPackage without first checking if
        // [`SecretShare::commitment()`] is the same for all participants using
        // a broadcast channel.
        let key_package: KeyPackage<C> = share.clone().try_into()?;
        let group = Group {
            ciphersuite: C::ID.to_string(),
            description: description.clone(),
            key_package: postcard::to_allocvec(&key_package)?,
            public_key_package: postcard::to_allocvec(&public_key_package)?,
            internal_key: internal_key_bytes.clone(),
            participant: participants.clone(),
            server_url: server_url.clone(),
        };
        config.group.insert(
            hex::encode(public_key_package.verifying_key().serialize()?),
            group,
        );
        for c in &contacts {
            config.contact.insert(c.name.clone(), c.clone());
        }
        config.write()?;
    }

    Ok(())
}
