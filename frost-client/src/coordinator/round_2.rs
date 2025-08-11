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

        // Get the internal public key P from the args
        // Note: cli.rs ensures this is always set for secp256k1-tr
        let internal_key = if let Some(internal_key_bytes) = &args.internal_key {
            XOnlyPublicKey::from_slice(internal_key_bytes)
                .map_err(|e| format!("Invalid internal key: {}", e))?
        } else {
            return Err("Internal key required for secp256k1-tr signing (should be set by cli.rs)".into());
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

    // If we are rerandomizing (secp256k1-tr), ensure aggregation verifies against P,
    // not Q. If the package already holds Q, rebuild a temporary package with P.
    let agg_result = if let Some(randomizer) = randomizer {
        use frost_core::keys::PublicKeyPackage as PKP;
        use frost_core::VerifyingKey as VK;
        use bitcoin::secp256k1::XOnlyPublicKey;

        // Determine whether the package contains Q (tweaked) or P (untweaked)
        let vk_bytes = participants
            .pub_key_package
            .verifying_key()
            .serialize()
            .map_err(|e| format!("Failed to serialize verifying key: {}", e))?;
        let pkg_xonly = match vk_bytes.len() {
            32 => XOnlyPublicKey::from_slice(&vk_bytes)
                .map_err(|e| format!("invalid x-only key in package: {}", e))?,
            33 => XOnlyPublicKey::from_slice(&vk_bytes[1..])
                .map_err(|e| format!("invalid compressed key in package: {}", e))?,
            65 => XOnlyPublicKey::from_slice(&vk_bytes[1..33])
                .map_err(|e| format!("invalid uncompressed key in package: {}", e))?,
            l => return Err(format!("unexpected verifying key length: {}", l).into()),
        };

        // Compute Q from P to compare
    use bitcoin::key::TapTweak;
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::verification_only();
        let internal_key = {
            let bytes = args
                .internal_key
                .clone()
                .ok_or("Internal key required for secp256k1-tr signing (should be set by cli.rs)")?;
            XOnlyPublicKey::from_slice(&bytes)
                .map_err(|e| format!("Invalid internal key: {}", e))?
        };
        let (computed_tweaked, _parity) = internal_key.tap_tweak(&secp, None);
        let computed_q_xonly: XOnlyPublicKey = computed_tweaked.into();

        // If package already has Q, rebuild a temporary package with P for aggregation
        let use_pkg = if pkg_xonly == computed_q_xonly {
            // Build compressed SEC1 for P (even-Y assumed for BIP-340)
            let mut p_sec1 = vec![0x02u8];
            p_sec1.extend_from_slice(&internal_key.serialize());
            let p_vk = VK::<C>::deserialize(&p_sec1)
                .map_err(|e| format!("cannot deserialize P verifying key: {}", e))?;
            PKP::new(
                participants.pub_key_package.verifying_shares().clone(),
                p_vk,
            )
        } else {
            participants.pub_key_package.clone()
        };

        let randomizer_params =
            frost_rerandomized::RandomizedParams::<C>::from_randomizer(
                use_pkg.verifying_key(),
                randomizer,
            );

        frost_rerandomized::aggregate(
            signing_package,
            &signatures_list,
            &use_pkg,
            &randomizer_params,
        )
    } else {
        // For all ciphersuites, use the standard aggregate function
        frost::aggregate::<C>(
            signing_package,
            &signatures_list,
            &participants.pub_key_package,
        )
    };

    // On error, print culprit details if available
    let group_signature = match agg_result {
        Ok(sig) => sig,
        Err(e) => {
            // Try to downcast/inspect the error for InvalidSignatureShare
            let err_str = format!("{}", e);
            if err_str.contains("InvalidSignatureShare") {
                // Best-effort parse of the culprit Identifier from Display string
                if let Some(start) = err_str.find("Identifier(\"") {
                    if let Some(end) = err_str[start + 12..].find('\"') {
                        let culprit_hex = &err_str[start + 12..start + 12 + end];
                        eprintln!("Invalid signature share from identifier: {}", culprit_hex);
                        // Map identifier -> verifying share if possible
                        if let Ok(id_bytes) = hex::decode(culprit_hex) {
                            if let Ok(id) = frost::Identifier::<C>::deserialize(&id_bytes) {
                                if let Some(vs) = participants
                                    .pub_key_package
                                    .verifying_shares()
                                    .get(&id)
                                {
                                    if let Ok(vs_hex) = vs.serialize().map(|b| hex::encode(b)) {
                                        eprintln!(
                                            "Verifying share (culprit): {}",
                                            vs_hex
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return Err(e.into());
        }
    };

    Ok(group_signature)
}

fn print_signature<C: Ciphersuite + 'static>(
    args: &ProcessedArgs<C>,
    logger: &mut dyn Write,
    group_signature: Signature<C>,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.signature.is_empty() || args.signature == "-" {
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
