use frost_core::{self as frost, Ciphersuite};

use frost::{Signature, SigningPackage};
use frost_rerandomized::{RandomizedCiphersuite, Randomizer};
use rand::thread_rng;
use reddsa::frost::redpallas::PallasBlake2b512;

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
    // Determine (optional) randomizer. Taproot now handled in dedicated round_2_tr.rs.
    let randomizer = if args.randomizers.is_empty() && C::ID == PallasBlake2b512::ID {
        let rng = thread_rng();
        Some(Randomizer::new(rng, signing_package)?)
    } else if args.randomizers.is_empty() {
        None
    } else {
        Some(args.randomizers[0])
    };

    let signatures_list = comms
        .send_signing_package_and_get_signature_shares(input, logger, signing_package, randomizer)
        .await?;

    // Aggregate signature shares (Taproot handled elsewhere).
    let agg_result = if let Some(randomizer) = randomizer {
        // Rerandomized flow (e.g. RedDSA) – shares verified under the randomized key parameters.
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
    } else {
        // Standard FROST aggregation.
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

pub fn print_signature<C: Ciphersuite + 'static>(
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
