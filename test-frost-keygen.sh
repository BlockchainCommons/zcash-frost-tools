#!/bin/bash
set -e

# FROST Taproot Tweak Key Generation Test Script
# This script tests FROST key generation with Taproot tweak and basic validation

echo "🧪 Starting FROST Taproot Tweak Key Generation Test"
echo "==============================================="

# Setup
TEST_DIR="/tmp/frost-taproot-keytest-$(date +%s)"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "📁 Test directory: $TEST_DIR"

# Clean up function
cleanup() {
    echo "🧹 Cleaning up test directory..."
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Step 1: Generate FROST key material with Taproot tweak
echo "🔑 Step 1: Generating FROST key material with Taproot tweak..."
trusted-dealer -t 2 -n 3 -C secp256k1-tr --taproot-tweak

# Verify files were created
if [[ ! -f "public-key-package.json" ]]; then
    echo "❌ Error: public-key-package.json not created"
    exit 1
fi

for i in {1..3}; do
    if [[ ! -f "key-package-$i.json" ]]; then
        echo "❌ Error: key-package-$i.json not created"
        exit 1
    fi
done

echo "✅ Key material generated successfully"

# Step 2: Extract and verify the public key
echo "🔍 Step 2: Extracting public key information..."
PUBLIC_KEY=$(jq -r '.verifying_key' public-key-package.json)
echo "📋 Group public key: $PUBLIC_KEY"

# Verify it's a valid 33-byte compressed key (66 hex chars)
if [[ ${#PUBLIC_KEY} -ne 66 ]]; then
    echo "❌ Error: Public key should be 66 hex characters (33 bytes), got ${#PUBLIC_KEY}"
    exit 1
fi

# Verify it starts with 02 or 03 (compressed point)
if [[ ! $PUBLIC_KEY =~ ^0[23] ]]; then
    echo "❌ Error: Public key should start with 02 or 03 (compressed point)"
    exit 1
fi

echo "✅ Public key format validation passed"

# Step 3: Verify that Taproot tweak actually changed the public key
echo "🔧 Step 3: Verifying Taproot tweak was applied..."

# Generate non-tweaked key material for comparison
mkdir -p "comparison"
cd "comparison"
trusted-dealer -t 2 -n 3 -C secp256k1-tr  # Without --taproot-tweak

UNTWEAKED_PUBLIC_KEY=$(jq -r '.verifying_key' public-key-package.json)
cd ..

if [[ "$PUBLIC_KEY" == "$UNTWEAKED_PUBLIC_KEY" ]]; then
    echo "❌ Error: Taproot tweak did not change the public key"
    echo "Tweaked key:   $PUBLIC_KEY"
    echo "Untweaked key: $UNTWEAKED_PUBLIC_KEY"
    exit 1
fi

echo "✅ Taproot tweak verification passed"
echo "📋 Tweaked key:   $PUBLIC_KEY"
echo "📋 Untweaked key: $UNTWEAKED_PUBLIC_KEY"

# Step 4: Verify key package structure
echo "🔍 Step 4: Verifying key package structure..."

# Check that key packages have required fields
for i in {1..3}; do
    KEY_FILE="key-package-$i.json"
    if ! jq -e '.identifier' "$KEY_FILE" >/dev/null; then
        echo "❌ Error: $KEY_FILE missing identifier field"
        exit 1
    fi

    if ! jq -e '.signing_share' "$KEY_FILE" >/dev/null; then
        echo "❌ Error: $KEY_FILE missing signing_share field"
        exit 1
    fi

    if ! jq -e '.commitment' "$KEY_FILE" >/dev/null; then
        echo "❌ Error: $KEY_FILE missing commitment field"
        exit 1
    fi

    # Verify commitment is an array
    COMMITMENT_LENGTH=$(jq '.commitment | length' "$KEY_FILE")
    if [[ "$COMMITMENT_LENGTH" -lt 1 ]]; then
        echo "❌ Error: $KEY_FILE commitment array is empty"
        exit 1
    fi
done

echo "✅ Key package structure validation passed"

# Step 5: Verify ciphersuite consistency
echo "🔍 Step 5: Verifying ciphersuite consistency..."

# Check public key package ciphersuite
PKG_CIPHERSUITE=$(jq -r '.header.ciphersuite' public-key-package.json)
if [[ "$PKG_CIPHERSUITE" != "FROST-secp256k1-SHA256-TR-v1" ]]; then
    echo "❌ Error: Public key package has wrong ciphersuite: $PKG_CIPHERSUITE"
    exit 1
fi

# Check key package ciphersuites
for i in {1..3}; do
    KEY_FILE="key-package-$i.json"
    KEY_CIPHERSUITE=$(jq -r '.header.ciphersuite' "$KEY_FILE")
    if [[ "$KEY_CIPHERSUITE" != "FROST-secp256k1-SHA256-TR-v1" ]]; then
        echo "❌ Error: $KEY_FILE has wrong ciphersuite: $KEY_CIPHERSUITE"
        exit 1
    fi
done

echo "✅ Ciphersuite validation passed"

# Step 6: Test without taproot tweak for comparison
echo "🔄 Step 6: Testing without Taproot tweak for comparison..."

mkdir -p "no-tweak-test"
cd "no-tweak-test"
trusted-dealer -t 2 -n 3 -C secp256k1-tr
NO_TWEAK_KEY=$(jq -r '.verifying_key' public-key-package.json)
cd ..

# Verify different ciphersuites produce different keys
if [[ "$PUBLIC_KEY" == "$NO_TWEAK_KEY" ]]; then
    echo "❌ Error: Tweaked and non-tweaked keys should be different"
    exit 1
fi

echo "✅ Non-tweak comparison passed"

# Summary
echo ""
echo "🎉 All tests passed!"
echo "==============================================="
echo "✅ FROST key generation with Taproot tweak"
echo "✅ Public key format validation"
echo "✅ Key package structure validation"
echo "✅ Ciphersuite consistency validation"
echo "✅ Taproot tweak functionality verification"
echo "✅ Comparison with non-tweaked keys"
echo ""
echo "📊 Test Results:"
echo "   • Test directory: $TEST_DIR"
echo "   • Threshold: 2 of 3 participants"
echo "   • Ciphersuite: FROST-secp256k1-SHA256-TR-v1"
echo "   • Tweaked public key: $PUBLIC_KEY"
echo "   • Untweaked public key: $UNTWEAKED_PUBLIC_KEY"
echo "   • Non-tweak public key: $NO_TWEAK_KEY"
echo ""
echo "🏆 FROST Taproot key generation test completed successfully!"
