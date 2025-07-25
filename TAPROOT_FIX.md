# FROST Taproot Integration Fix

## Problem Statement

The FROST + BDK integration demo fails at transaction broadcast with the error:

```
mandatory-script-verify-flag-failed (Invalid Schnorr signature), input 0 of
9c0f7ca6588a6aca27a378e9d48f8f947c59c5ad76e89f6226d20ffec815758c
```

This occurs when attempting to spend a Taproot (P2TR) output using a FROST-generated signature. The signature is cryptographically valid but fails Bitcoin's consensus validation.

## Root Cause Analysis

### The Taproot Tweak Mismatch

Bitcoin's BIP-341 Taproot specification requires that all key-path spends use **tweaked** public keys. When a P2TR output is created, the actual key stored in the UTXO is not the raw public key `P`, but a tweaked version:

```
Q = P + H_tapTweak(P || merkle_root) * G
```

Where:
- `P` = Internal (aggregate) public key from FROST
- `Q` = Tweaked public key that appears in the UTXO
- `H_tapTweak()` = BIP-341 taproot tweak hash function
- `merkle_root` = Script tree root (empty for key-path spends)

### Current Implementation Issue

The FROST tools correctly apply taproot tweaking **to the public key** but **not to the secret shares**:

1. **✅ Public Key Tweaking**: In `trusted_dealer_for_ciphersuite()` ([trusted_dealer.rs:77-88](frost-client/src/cli/trusted_dealer.rs)):
   ```rust
   if C::ID == Secp256K1Sha256TR::ID {
       let p_bytes = public_key_package.verifying_key().serialize()?;
       let p_xonly = XOnlyPublicKey::from_slice(&p_bytes).expect("x-only key");
       let (q_key, _t) = tweak_internal_key(p_xonly);  // Q = P + t*G

       let q_vk = VerifyingKey::<C>::deserialize(&q_key.serialize())?;
       public_key_package = PublicKeyPackage::new(
           public_key_package.verifying_shares().clone(),
           q_vk,  // Store Q instead of P
       );
   }
   ```

2. **❌ Secret Shares Not Tweaked**: The `MaybeIntoEvenY` trait for `secp256k1-tr` uses the default implementation:
   ```rust
   impl MaybeIntoEvenY for frost_secp256k1_tr::Secp256K1Sha256TR {}
   ```

   This leaves participant secret shares unchanged, so they still correspond to the original key `P`.

### The Signature Verification Failure

This creates a fundamental mismatch:

- **FROST signs with**: Untweaked secret shares (corresponding to `P`)
- **Bitcoin verifies against**: Tweaked public key `Q` (stored in UTXO)
- **Result**: Signature verification fails because `sig_P` ≠ `sig_Q`

The signature is mathematically valid for key `P`, but Bitcoin's consensus rules require it to be valid for key `Q`.

## Technical Deep Dive

### BIP-341 Taproot Key Tweaking

BIP-341 mandates that every taproot output uses a tweaked public key. For key-path spending (no script tree), the tweak is:

```
t = H_tapTweak(P_x || 0x00)  // Hash of x-coordinate + empty merkle root
Q = P + t*G                  // Tweaked public key
```

For a valid signature under `Q`, either:
1. **Option A**: Sign with tweaked private key: `sk' = sk + t`
2. **Option B**: Pre-compute `Q` and ensure all operations use `Q` consistently

### Current FROST Implementation Analysis

The current code attempts **Option B** but implements it incorrectly:

```rust
// In trusted_dealer.rs - This part works correctly
let (q_key, _t) = tweak_internal_key(p_xonly);  // Computes Q = P + t*G
public_key_package = PublicKeyPackage::new(
    public_key_package.verifying_shares().clone(),
    q_vk,  // Updates verifying_key to Q
);
```

However, the participant secret shares remain untweaked:

```rust
// In mod.rs - This is the problem
impl MaybeIntoEvenY for frost_secp256k1_tr::Secp256K1Sha256TR {}
// Uses default implementation - no secret share modification
```

When participants sign, they use their original shares (valid for `P`) to create signatures, but Bitcoin expects signatures valid for `Q`.

## Recommended Fix: Option 1 (Tweak Secret Shares)

The most elegant solution is to implement **Option A**: modify secret shares to include the taproot tweak.

### Implementation Plan

1. **Modify the `MaybeIntoEvenY` trait** for `secp256k1-tr` to tweak secret shares:

```rust
impl MaybeIntoEvenY for frost_secp256k1_tr::Secp256K1Sha256TR {
    fn into_even_y(
        (secret_shares, public_key_package): (
            BTreeMap<Identifier<Self>, SecretShare<Self>>,
            PublicKeyPackage<Self>,
        ),
    ) -> (
        BTreeMap<Identifier<Self>, SecretShare<Self>>,
        PublicKeyPackage<Self>,
    ) {
        // 1. Compute taproot tweak scalar
        let p_bytes = public_key_package.verifying_key().serialize().unwrap();
        let p_xonly = XOnlyPublicKey::from_slice(&p_bytes[1..]).unwrap();
        let (_q_key, tweak_scalar) = tweak_internal_key(p_xonly);

        // 2. Add tweak to each secret share: s_i' = s_i + t
        let tweaked_shares = secret_shares
            .iter()
            .map(|(id, share)| {
                let tweaked_share = share.clone().add_tweak(tweak_scalar);
                (*id, tweaked_share)
            })
            .collect();

        // 3. Update public key to Q = P + t*G
        let q_vk = compute_tweaked_verifying_key(&public_key_package, tweak_scalar);
        let tweaked_package = PublicKeyPackage::new(
            public_key_package.verifying_shares().clone(),
            q_vk,
        );

        (tweaked_shares, tweaked_package)
    }
}
```

2. **Add helper functions** for secret share tweaking (these may need to be added to the FROST library):

```rust
// Extension trait for SecretShare tweaking
trait TaprootTweak {
    fn add_tweak(self, tweak: Scalar) -> Self;
}

impl TaprootTweak for SecretShare<Secp256K1Sha256TR> {
    fn add_tweak(mut self, tweak: Scalar) -> Self {
        // Add tweak scalar to the signing share
        // This requires access to SecretShare internals
        self.signing_share = self.signing_share + tweak;
        self
    }
}
```

3. **Remove explicit tweaking** from `trusted_dealer_for_ciphersuite()` since it will be handled by `MaybeIntoEvenY`.

### Benefits of This Approach

- **Mathematically Correct**: Participants sign with `sk_i + t`, producing signatures valid under `Q`
- **Follows FROST Design**: Leverages existing `MaybeIntoEvenY` infrastructure
- **Bitcoin Compatible**: Signatures verify correctly under Bitcoin's consensus rules
- **Clean Architecture**: Separates taproot logic from general FROST signing

### Required Changes

1. **frost_secp256k1_tr crate**: May need to expose methods for secret share arithmetic
2. **frost-client**: Implement custom `MaybeIntoEvenY` for `secp256k1-tr`
3. **Remove manual tweaking**: Clean up explicit public key tweaking in `trusted_dealer.rs`

## Alternative Fix: Option 2 (Use Tweaked Keys Consistently)

If modifying secret shares proves difficult, ensure the entire pipeline uses the tweaked key `Q`:

1. **Keep current public key tweaking**
2. **Update descriptor generation** to use the correctly tweaked key
3. **Ensure sighash computation** uses the tweaked key consistently
4. **Verify FROST library** handles tweaked keys properly during aggregation

However, this approach is more error-prone and doesn't follow the standard taproot signing pattern.

## Testing Strategy

1. **Unit Tests**: Verify secret share tweaking math
2. **Integration Tests**: Test complete FROST ceremony with tweaked shares
3. **Bitcoin Integration**: Confirm transactions broadcast successfully on regtest
4. **Compatibility Tests**: Ensure tweaked signatures verify with standard Bitcoin tools

## Impact Assessment

- **Breaking Change**: Yes, changes the `secp256k1-tr` key generation behavior
- **Backward Compatibility**: Existing `secp256k1-tr` keys would be incompatible
- **Performance Impact**: Minimal (one scalar addition per participant)
- **Security Impact**: None (mathematically equivalent to standard taproot signing)

## Migration Path

1. **Version the change**: Bump ciphersuite version to indicate breaking change
2. **Clear documentation**: Explain the fix and incompatibility with old keys
3. **Example updates**: Update all demos and documentation
4. **Deprecation notice**: Mark old behavior as deprecated

## Conclusion

The current FROST taproot integration applies tweaking inconsistently, causing signature verification failures. The recommended fix is to implement proper secret share tweaking in the `MaybeIntoEvenY` trait, ensuring signatures are valid under the tweaked public key that actually appears in Bitcoin UTXOs.

This fix aligns the FROST implementation with BIP-341 requirements and enables successful taproot key-path spending with threshold signatures.
