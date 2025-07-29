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
        // For secp256k1-tr, compute BIP-341 Taproot tweak
        // Use the verifying key from the public key package as the internal key
        use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
        use bitcoin::key::TapTweak;
        use bitcoin::taproot::TapTweakHash;
        use bitcoin::hashes::Hash;
        use k256::{Scalar, elliptic_curve::PrimeField};

        // Get the internal public key from the FROST verifying key
        let verifying_key = participants.pub_key_package.verifying_key();
        let vk_bytes = verifying_key.serialize()
            .map_err(|e| format!("Failed to serialize verifying key: {}", e))?;

        // Extract x-only public key (skip the 0x02/0x03 prefix for compressed format)
        let internal_key = XOnlyPublicKey::from_slice(&vk_bytes[1..])
            .map_err(|e| format!("Invalid internal key from verifying key: {}", e))?;

        let secp = Secp256k1::verification_only();

        // Compute the tweak: Q = P + H_TapTweak(P || 0) * G
        let (_tweaked_key, _parity) = internal_key.tap_tweak(&secp, None);

        // Get the tweak hash directly
        let tweak_hash = TapTweakHash::from_key_and_tweak(internal_key, None);
        let tweak_bytes = tweak_hash.to_byte_array();

        // Convert the 32-byte tweak to a scalar
        // For k256, from_repr returns a CtOption<Scalar>
        let tweak_scalar = Scalar::from_repr(tweak_bytes.into())
            .unwrap_or_else(|| {
                // If the hash is larger than the curve order, reduce it by taking modulo
                // This is a rare case but can happen with some hash values
                use k256::elliptic_curve::ops::Reduce;
                <Scalar as Reduce<k256::U256>>::reduce_bytes(&tweak_bytes.into())
            });

        // Create randomizer from the tweak scalar
        let randomizer_bytes = tweak_scalar.to_bytes();
        let randomizer = Randomizer::deserialize(&randomizer_bytes)?;

        eprintln!("Applied BIP-341 Taproot tweak for secp256k1-tr signing");
        eprintln!("Internal key (x-only): {}", hex::encode(internal_key.serialize()));
        eprintln!("Tweak scalar: {}", hex::encode(&tweak_bytes));

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
