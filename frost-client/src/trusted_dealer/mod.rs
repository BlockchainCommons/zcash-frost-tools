pub mod args;
pub mod cli;
pub mod inputs;
pub mod trusted_dealer_keygen;

// TODO: fix and restore tests
// #[cfg(test)]
// mod tests;

pub use inputs::Config;

use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

use frost_core::keys::{IdentifierList, PublicKeyPackage, SecretShare};
use frost_core::{Ciphersuite, Identifier, VerifyingKey};
use reddsa::frost::redpallas::keys::EvenY;
use bitcoin::key::XOnlyPublicKey;

use trusted_dealer_keygen::{split_secret, trusted_dealer_keygen};

// The redpallas ciphersuite, when used for generating Orchard spending key
// signatures, requires ensuring public key have an even Y coordinate. Since the
// code uses generics, this trait is used to convert if needed depending on the
// ciphersuite.
//
// If you are adding a new ciphersuite to this tool which does note require
// this, just implement it and the default implementation (which does nothing)
// will suffice. See below.
pub trait MaybeIntoEvenY: Ciphersuite {
    fn into_even_y(
        secret_shares_and_public_key_package: (
            BTreeMap<Identifier<Self>, SecretShare<Self>>,
            PublicKeyPackage<Self>,
        ),
    ) -> (
        BTreeMap<Identifier<Self>, SecretShare<Self>>,
        PublicKeyPackage<Self>,
    ) {
        secret_shares_and_public_key_package
    }
}

// A ciphersuite that does not need the conversion.
impl MaybeIntoEvenY for frost_ed25519::Ed25519Sha512 {}

impl MaybeIntoEvenY for frost_secp256k1_tr::Secp256K1Sha256TR {}

impl MaybeIntoEvenY for reddsa::frost::redpallas::PallasBlake2b512 {
    fn into_even_y(
        (secret_shares, public_key_package): (
            BTreeMap<Identifier<Self>, SecretShare<Self>>,
            PublicKeyPackage<Self>,
        ),
    ) -> (
        BTreeMap<Identifier<Self>, SecretShare<Self>>,
        PublicKeyPackage<Self>,
    ) {
        let is_even = public_key_package.has_even_y();
        let public_key_package = public_key_package.into_even_y(Some(is_even));
        let secret_shares = secret_shares
            .iter()
            .map(|(i, s)| (*i, s.clone().into_even_y(Some(is_even))))
            .collect();
        (secret_shares, public_key_package)
    }
}

#[allow(clippy::type_complexity)]
pub fn trusted_dealer<C: Ciphersuite + 'static + MaybeIntoEvenY, R: RngCore + CryptoRng>(
    config: &Config,
    rng: &mut R,
) -> Result<
    (BTreeMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>),
    Box<dyn std::error::Error>,
> {
    let shares_and_package = if config.secret.is_empty() {
        trusted_dealer_keygen(config, IdentifierList::<C>::Default, rng)?
    } else {
        split_secret(config, IdentifierList::<C>::Default, rng)?
    };

    let (shares, mut public_key_package) = MaybeIntoEvenY::into_even_y(shares_and_package);

    // Optionally apply Taproot tweak (only makes sense for secp256k1‑TR)
    if config.taproot_tweak && C::ID == frost_secp256k1_tr::Secp256K1Sha256TR::ID {
        use crate::util::taproot::tweak_internal_key;

        // (1) untweaked P
        let p_bytes = public_key_package.verifying_key().serialize()?;
        // Extract x-coordinate from SEC1 compressed format (skip first byte)
        let p_xonly = XOnlyPublicKey::from_slice(&p_bytes[1..])
            .map_err(|e| format!("cannot parse internal key: {:?}", e))?;

        // (2) tweak -> Q
        let (q_key, _t) = tweak_internal_key(p_xonly);

        // (3) build a fresh PublicKeyPackage with the tweaked key Q
        // Need to convert x-only (32 bytes) back to compressed SEC1 format (33 bytes)
        let mut q_bytes = vec![0x02]; // compressed point prefix
        q_bytes.extend_from_slice(&q_key.serialize());

        let q_vk = VerifyingKey::<C>::deserialize(&q_bytes)
            .map_err(|e| format!("cannot deserialize tweaked key: {:?}", e))?;

        public_key_package = PublicKeyPackage::new(
            public_key_package.verifying_shares().clone(), // getter from derive_getters
            q_vk,
        );
    }

    Ok((shares, public_key_package))
}
