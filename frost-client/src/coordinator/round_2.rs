use frost_core::{self as frost, Ciphersuite};

use frost::{Signature, SigningPackage};
use frost_rerandomized::{RandomizedCiphersuite, Randomizer};
use rand::thread_rng;
use reddsa::frost::redpallas::PallasBlake2b512;
use frost_secp256k1_tr::Secp256K1Sha256TR;

use std::{
    fs,
    io::{BufRead, Write},
};

use super::{args::ProcessedArgs, comms::Comms, round_1::ParticipantsConfig};

pub async fn send_signing_package_and_get_signature_shares<C: RandomizedCiphersuite + 'static>(
    args: &ProcessedArgs<C>,
    comms: &mut dyn Comms<C>,
    input: &mut dyn BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig<C>,
    signing_package: &SigningPackage<C>,
) -> Result<Signature<C>, Box<dyn std::error::Error>> {
    let group_signature =
        request_inputs_signature_shares(args, comms, input, logger, participants, signing_package)
            .await?;
    print_signature(args, logger, group_signature)?;
    Ok(group_signature)
}

// Input required:
// 1. number of signers (TODO: maybe pass this in?)
// 2. signatures for all signers
async fn request_inputs_signature_shares<C: RandomizedCiphersuite + 'static>(
    args: &ProcessedArgs<C>,
    comms: &mut dyn Comms<C>,
    input: &mut dyn BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig<C>,
    signing_package: &SigningPackage<C>,
) -> Result<Signature<C>, Box<dyn std::error::Error>> {
    // TODO: support multiple
    let randomizer = if args.randomizers.is_empty() && C::ID == PallasBlake2b512::ID {
        let rng = thread_rng();
        Some(Randomizer::new(rng, signing_package)?)
    } else if args.randomizers.is_empty() && C::ID == Secp256K1Sha256TR::ID {
        // For secp256k1-tr, the public key package should already contain the tweaked key Q
        // We need to apply the tweak scalar as a randomizer to adjust the secret shares
        use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
        use bitcoin::key::TapTweak;
        use bitcoin::taproot::TapTweakHash;
        use bitcoin::hashes::Hash;
        use k256::{Scalar, elliptic_curve::PrimeField};

        // Get the internal public key P from the args (stored during DKG)
        let internal_key = if let Some(internal_key_bytes) = &args.internal_key {
            XOnlyPublicKey::from_slice(internal_key_bytes)
                .map_err(|e| format!("Invalid internal key: {}", e))?
        } else {
            return Err("Internal key required for secp256k1-tr signing".into());
        };

        let secp = Secp256k1::verification_only();

        // Compute the tweak: Q = P + H_TapTweak(P || 0) * G
        let (tweaked_key, _parity) = internal_key.tap_tweak(&secp, None);
        let tweaked_key_xonly: XOnlyPublicKey = tweaked_key.into();

        // Verify that the public key package contains the correct tweaked key
        let verifying_key = participants.pub_key_package.verifying_key();
        let vk_bytes = verifying_key.serialize()
            .map_err(|e| format!("Failed to serialize verifying key: {}", e))?;
        let package_key = XOnlyPublicKey::from_slice(&vk_bytes[1..])
            .map_err(|e| format!("Invalid key from public key package: {}", e))?;

        if package_key != tweaked_key_xonly {
            eprintln!("Warning: Public key package key doesn't match computed tweaked key");
            eprintln!("Package key: {}", hex::encode(package_key.serialize()));
            eprintln!("Computed tweaked key: {}", hex::encode(tweaked_key_xonly.serialize()));
        }

        // Get the tweak hash directly
        let tweak_hash = TapTweakHash::from_key_and_tweak(internal_key, None);
        let tweak_bytes = tweak_hash.to_byte_array();

        // Convert the 32-byte tweak to a scalar
        let tweak_scalar = Scalar::from_repr(tweak_bytes.into())
            .unwrap_or_else(|| {
                // If the hash is larger than the curve order, reduce it by taking modulo
                use k256::elliptic_curve::ops::Reduce;
                <Scalar as Reduce<k256::U256>>::reduce_bytes(&tweak_bytes.into())
            });

        // Create randomizer from the tweak scalar
        let randomizer_bytes = tweak_scalar.to_bytes();
        let randomizer = Randomizer::deserialize(&randomizer_bytes)?;

        eprintln!("Applied BIP-341 Taproot tweak for secp256k1-tr signing");
        eprintln!("Internal key (x-only): {}", hex::encode(internal_key.serialize()));
        eprintln!("Tweak scalar: {}", hex::encode(&tweak_bytes));
        eprintln!("Tweaked key (x-only): {}", hex::encode(tweaked_key_xonly.serialize()));

        Some(randomizer)
    } else if args.randomizers.is_empty() {
        None
    } else {
        Some(args.randomizers[0])
    };

    let signatures_list = comms
        .send_signing_package_and_get_signature_shares(input, logger, signing_package, randomizer)
        .await?;

    let group_signature = if let Some(randomizer) = randomizer {
        let randomizer_params = frost_rerandomized::RandomizedParams::<C>::from_randomizer(
            participants.pub_key_package.verifying_key(),
            randomizer,
        );

        frost_rerandomized::aggregate(
            signing_package,
            &signatures_list,
            &participants.pub_key_package,
            &randomizer_params,
        )
        .unwrap()
    } else if C::ID == Secp256K1Sha256TR::ID {
        // For secp256k1-tr without explicit randomizer, use aggregate_with_tweak
        // to properly add the BIP-341 tweak term to the s-value
        use frost_secp256k1_tr::aggregate_with_tweak;
        use crate::util::taproot::tweak_internal_key;

        // Get the internal key to compute the tweak
        let internal_key = if let Some(internal_key_bytes) = &args.internal_key {
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(internal_key_bytes)
                .map_err(|e| format!("Invalid internal key: {}", e))?
        } else {
            return Err("Internal key required for secp256k1-tr aggregation".into());
        };

        // Compute the BIP-341 tweak scalar using our utility function
        let (_tweaked_key, tweak_scalar) = tweak_internal_key(internal_key);

        eprintln!("Using aggregate_with_tweak for BIP-341 Taproot signature");
        eprintln!("Internal key: {}", hex::encode(internal_key.serialize()));
        eprintln!("Tweak scalar: {}", hex::encode(tweak_scalar.to_be_bytes()));

        // Cast the generic types to the specific secp256k1-tr types
        // This is safe because we've already checked C::ID == Secp256K1Sha256TR::ID
        use std::mem;

        // SAFETY: We've verified that C is Secp256K1Sha256TR via the type ID check above
        let secp_signing_package: &frost_core::SigningPackage<frost_secp256k1_tr::Secp256K1Sha256TR> =
            unsafe { mem::transmute(signing_package) };
        let secp_signatures: &std::collections::BTreeMap<frost_core::Identifier<frost_secp256k1_tr::Secp256K1Sha256TR>, frost_core::round2::SignatureShare<frost_secp256k1_tr::Secp256K1Sha256TR>> =
            unsafe { mem::transmute(&signatures_list) };
        let secp_pub_key_package: &frost_core::keys::PublicKeyPackage<frost_secp256k1_tr::Secp256K1Sha256TR> =
            unsafe { mem::transmute(&participants.pub_key_package) };

        let secp_signature = aggregate_with_tweak(
            secp_signing_package,
            secp_signatures,
            secp_pub_key_package,
            None,  // merkle_root for BIP-341 basic Taproot (no script tree)
        )?;

        // Convert the secp256k1-tr signature back to the generic type
        // by serializing and deserializing
        let signature_bytes = secp_signature.serialize()?;
        let generic_signature = frost_core::Signature::<C>::deserialize(&signature_bytes)?;
        generic_signature
    } else {
        // For all other ciphersuites (including non-tweaked keys),
        // use the standard aggregate function
        frost::aggregate::<C>(
            signing_package,
            &signatures_list,
            &participants.pub_key_package,
        )
        .unwrap()
    };

    Ok(group_signature)
}

fn print_signature<C: Ciphersuite + 'static>(
    args: &ProcessedArgs<C>,
    logger: &mut dyn Write,
    group_signature: Signature<C>,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.signature.is_empty() {
        writeln!(
            logger,
            "Signature:\n{}",
            hex::encode(&group_signature.serialize()?)
        )?;
    } else {
        fs::write(&args.signature, group_signature.serialize()?)?;
        eprintln!("Raw signature written to {}", &args.signature);
    };
    Ok(())
}
