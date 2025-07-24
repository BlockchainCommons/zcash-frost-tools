# FROST Taproot Tweak Integration Tests

This document describes the integration tests for FROST signing with Taproot tweak functionality.

## Overview

The FROST tools now support Taproot tweaking for the `secp256k1-tr` ciphersuite. When enabled, this applies BIP-341 Taproot tweaking to the generated group public key, making it suitable for use in Bitcoin Taproot transactions.

## Usage

### Basic Key Generation

```bash
# Generate FROST key material
trusted-dealer -t 2 -n 3 -C secp256k1-tr

# This creates:
# - public-key-package.json (contains the tweaked group public key)
# - key-package-1.json, key-package-2.json, key-package-3.json (individual participant keys)
```

### Comparison with Non-Tweaked Keys

```bash
# Generate non-tweaked keys for comparison
trusted-dealer -t 2 -n 3 -C secp256k1-tr

# The public keys will be different between tweaked and non-tweaked versions
```

## Integration Tests

### Bash Test Script

A comprehensive bash script tests the complete workflow:

```bash
./test-frost-keygen.sh
```

This script:
- ✅ Generates FROST key material with Taproot tweak
- ✅ Validates public key format (33-byte compressed)
- ✅ Verifies key package structure consistency
- ✅ Confirms ciphersuite is `FROST-secp256k1-SHA256-TR-v1`
- ✅ Ensures Taproot tweak changes the public key
- ✅ Compares tweaked vs non-tweaked keys

### Rust Integration Tests

Run the Rust tests with:

```bash
cargo test -p tests taproot --verbose
```

This runs three test functions:

1. **`test_frost_taproot_tweak_integration`**
   - Generates keys with and without Taproot tweak
   - Verifies they produce different public keys
   - Validates file structure and formats

2. **`test_taproot_tweak_consistency`**
   - Ensures different runs produce different keys (randomness check)
   - Validates that the tweak is being applied correctly

3. **`test_taproot_tweak_field_validation`**
   - Tests the `Config` struct with `taproot_tweak` field
   - Verifies the field can be set to `true` and `false`

## Key Technical Details

### Taproot Tweak Implementation

The implementation follows BIP-341 Taproot specification:

1. **Input**: FROST group public key P (33-byte compressed SEC1 format)
2. **Extract x-coordinate**: Convert to 32-byte x-only format
3. **Apply tweak**: `Q = P + H_TapTweak(P_x || merkle_root) * G` (merkle_root = empty)
4. **Output**: Tweaked public key Q (converted back to 33-byte compressed format)

### File Structure

**Public Key Package** (`public-key-package.json`):
```json
{
  "header": {
    "version": 0,
    "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
  },
  "verifying_shares": { /* participant verifying shares */ },
  "verifying_key": "02..." // 33-byte compressed tweaked public key
}
```

**Key Package** (`key-package-N.json`):
```json
{
  "header": {
    "version": 0,
    "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
  },
  "identifier": "000...001",
  "signing_share": "...", // participant's secret share
  "commitment": ["...", "..."] // commitment points
}
```

## Validation Checks

The tests perform comprehensive validation:

- **Format validation**: Public keys are 66 hex characters (33 bytes)
- **Compression validation**: Keys start with `02` or `03`
- **Ciphersuite validation**: All components use `FROST-secp256k1-SHA256-TR-v1`
- **Tweak validation**: Tweaked keys differ from untweaked keys
- **Structure validation**: All required JSON fields are present
- **Randomness validation**: Different runs produce different keys

## Example Output

```
🎉 All tests passed!
===============================================
✅ FROST key generation with Taproot tweak
✅ Public key format validation
✅ Key package structure validation
✅ Ciphersuite consistency validation
✅ Taproot tweak functionality verification
✅ Comparison with non-tweaked keys

📊 Test Results:
   • Threshold: 2 of 3 participants
   • Ciphersuite: FROST-secp256k1-SHA256-TR-v1
   • Tweaked public key: 029e696377f5577cca966050fc2eae9741e503aafed7692bd3ea1fee3075fb69fc
   • Untweaked public key: 03efb85a07bfbf07e256ddfff541dc6bcac4e00d48aaaf2399470f451b8f64325e
```

## Usage in Bitcoin Applications

The tweaked public key can be used directly in Bitcoin Taproot outputs:

1. Extract the tweaked public key from `public-key-package.json`
2. Convert to x-only format (remove first byte): `9e696377f5577cca966050fc2eae9741e503aafed7692bd3ea1fee3075fb69fc`
3. Use in Taproot output scripts (OP_1 + 32 bytes)

The FROST signing process will need to account for the tweak when generating signatures for Taproot key-path spends.
