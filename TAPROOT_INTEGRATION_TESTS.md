# FROST Taproot Integration Tests

This document describes the integration tests for FROST signing with Taproot functionality.

## Overview

The FROST tools support Taproot tweaking for the `secp256k1-tr` ciphersuite. This automatically applies BIP-341 Taproot tweaking to the generated group public key, making it suitable for use in Bitcoin Taproot transactions.

## Usage

### Basic Key Generation

```bash
# Generate FROST key material with automatic Taproot tweaking
trusted-dealer -t 2 -n 3 -C secp256k1-tr

# This creates:
# - public-key-package.json (contains the Taproot-tweaked group public key)
# - key-package-1.json, key-package-2.json, key-package-3.json (individual participant keys)
```

### Complete Signing Ceremony

```bash
# Generate keys
trusted-dealer -t 2 -n 3 -C secp256k1-tr

# Run signing ceremony (see test-frost-taproot.sh for complete workflow)
coordinator -C secp256k1-tr --public-key-package public-key-package.json --message message.txt --num-signers 2 &
participant -C secp256k1-tr -k key-package-1.json --ip 127.0.0.1 --port 12744 &
participant -C secp256k1-tr -k key-package-2.json --ip 127.0.0.1 --port 12744 &
```

## Integration Tests

### Shell Script Test

A bash script tests the complete workflow:

```bash
./test-frost-taproot.sh
```

This script performs a full FROST signing ceremony with:
- ✅ Taproot key generation
- ✅ Coordinator/participant orchestration
- ✅ Signature generation
- ✅ Cryptographic signature verification
- ✅ Taproot validation

### Rust Integration Tests

Run the Rust tests with:

```bash
cargo test --package tests --verbose
```

This runs four main test functions:

1. **`test_frost_taproot_tweak_integration`**
   - CLI-based key generation with secp256k1-tr
   - Validates public key format and structure
   - Confirms Taproot changes the public key

2. **`test_taproot_tweak_consistency`**
   - Ensures different runs produce different keys (randomness)
   - Validates deterministic behavior within single runs

3. **`test_complete_frost_taproot_library_signing`**
   - Full FROST ceremony using library calls directly
   - Manual Taproot tweaking demonstration
   - Complete cryptographic verification

4. **`test_cli_frost_taproot_signing_ceremony`**
   - Full FROST ceremony using CLI tools
   - Network-based coordinator/participant communication
   - End-to-end signature verification

## Technical Implementation

### Automatic Taproot Detection

Taproot tweaking is **automatic** when using the `secp256k1-tr` ciphersuite:
- No flags or special configuration needed
- The `trusted-dealer` automatically applies BIP-341 tweaking
- All keys generated are Taproot-ready

### BIP-341 Taproot Specification

The implementation follows the BIP-341 standard:

1. **Key Generation**: FROST generates a group public key P
2. **Taproot Tweak**: Applies `Q = P + H_TapTweak(P_x) * G` (no script tree)
3. **Output**: Tweaked public key Q suitable for Taproot key-path spending

### File Structure

Generated files use the `FROST-secp256k1-SHA256-TR-v1` ciphersuite:

```json
// public-key-package.json
{
  "header": { "ciphersuite": "FROST-secp256k1-SHA256-TR-v1" },
  "verifying_key": "02...", // 33-byte compressed Taproot-tweaked key
  "verifying_shares": { /* participant shares */ }
}

// key-package-N.json
{
  "header": { "ciphersuite": "FROST-secp256k1-SHA256-TR-v1" },
  "identifier": "000...001",
  "signing_share": "...",
  "commitment": ["...", "..."]
}
```

## Test Validation

All tests perform full validation:

- **Cryptographic verification**: All signatures are verified using `verifying_key.verify()`
- **Format validation**: 66-character hex keys starting with `02`/`03`
- **Ciphersuite validation**: All components use `secp256k1-tr`
- **Taproot validation**: Different runs produce different keys
- **End-to-end validation**: Complete signing ceremonies from key generation to verification

## Usage in Bitcoin Applications

The Taproot-tweaked public key can be used directly in Bitcoin:

1. Extract the public key from `public-key-package.json`
2. Convert to x-only format (remove first byte): `9e696377...fb69fc`
3. Use in Taproot outputs: `OP_1 <32-byte-x-only-key>`

FROST signatures generated with these keys are valid for Taproot key-path spending.
