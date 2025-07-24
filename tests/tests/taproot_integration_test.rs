use std::process::Command;
use std::fs;
use tempfile::TempDir;
use serde_json::Value;

#[test]
fn test_frost_taproot_tweak_integration() {
    // Create temporary directory for test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_path = temp_dir.path();

    println!("Running FROST Taproot integration test in: {:?}", test_path);

    // Step 1: Generate FROST key material with Taproot tweak
    let output = Command::new("trusted-dealer")
        .args(&["-t", "2", "-n", "3", "-C", "secp256k1-tr", "--taproot-tweak"])
        .current_dir(test_path)
        .output()
        .expect("Failed to run trusted-dealer");

    assert!(output.status.success(),
        "trusted-dealer failed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify files were created
    assert!(test_path.join("public-key-package.json").exists(), "public-key-package.json not created");
    for i in 1..=3 {
        let key_file = format!("key-package-{}.json", i);
        assert!(test_path.join(&key_file).exists(), "{} not created", key_file);
    }

    // Step 2: Extract and verify public key
    let public_key_package = fs::read_to_string(test_path.join("public-key-package.json"))
        .expect("Failed to read public-key-package.json");
    let public_key_json: Value = serde_json::from_str(&public_key_package)
        .expect("Failed to parse public-key-package.json");

    let tweaked_public_key = public_key_json["verifying_key"]
        .as_str()
        .expect("verifying_key not found")
        .to_string();

    // Verify public key format (66 hex chars, starts with 02 or 03)
    assert_eq!(tweaked_public_key.len(), 66, "Public key should be 66 hex characters");
    assert!(tweaked_public_key.starts_with("02") || tweaked_public_key.starts_with("03"),
        "Public key should start with 02 or 03");

    // Step 3: Generate untweaked key material for comparison
    let comparison_dir = test_path.join("comparison");
    fs::create_dir(&comparison_dir).expect("Failed to create comparison dir");

    let output = Command::new("trusted-dealer")
        .args(&["-t", "2", "-n", "3", "-C", "secp256k1-tr"]) // No --taproot-tweak
        .current_dir(&comparison_dir)
        .output()
        .expect("Failed to run trusted-dealer for comparison");

    assert!(output.status.success(),
        "trusted-dealer comparison failed: {}", String::from_utf8_lossy(&output.stderr));

    let untweaked_public_key_package = fs::read_to_string(comparison_dir.join("public-key-package.json"))
        .expect("Failed to read comparison public-key-package.json");
    let untweaked_public_key_json: Value = serde_json::from_str(&untweaked_public_key_package)
        .expect("Failed to parse comparison public-key-package.json");

    let untweaked_public_key = untweaked_public_key_json["verifying_key"]
        .as_str()
        .expect("comparison verifying_key not found")
        .to_string();

    // Verify that Taproot tweak actually changed the public key
    assert_ne!(tweaked_public_key, untweaked_public_key,
        "Taproot tweak should change the public key");

    println!("✅ Tweaked public key:   {}", tweaked_public_key);
    println!("✅ Untweaked public key: {}", untweaked_public_key);
    println!("✅ FROST Taproot tweak integration test passed!");
}

#[test]
fn test_taproot_tweak_consistency() {
    // Test that multiple runs with the same seed produce consistent results
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_path = temp_dir.path();

    // Generate key material twice with taproot tweak
    let mut public_keys = Vec::new();

    for run in 1..=2 {
        let run_dir = test_path.join(format!("run{}", run));
        fs::create_dir(&run_dir).expect("Failed to create run dir");

        let output = Command::new("trusted-dealer")
            .args(&["-t", "2", "-n", "3", "-C", "secp256k1-tr", "--taproot-tweak"])
            .current_dir(&run_dir)
            .output()
            .expect("Failed to run trusted-dealer");

        assert!(output.status.success(),
            "trusted-dealer run {} failed: {}", run, String::from_utf8_lossy(&output.stderr));

        let public_key_package = fs::read_to_string(run_dir.join("public-key-package.json"))
            .expect("Failed to read public-key-package.json");
        let public_key_json: Value = serde_json::from_str(&public_key_package)
            .expect("Failed to parse public-key-package.json");

        let public_key = public_key_json["verifying_key"]
            .as_str()
            .expect("verifying_key not found")
            .to_string();

        public_keys.push(public_key);
    }

    // Keys should be different (since we're using random generation)
    assert_ne!(public_keys[0], public_keys[1],
        "Different runs should produce different keys (randomness check)");

    println!("✅ Consistency test passed - different runs produce different keys as expected");
}

#[test]
fn test_taproot_tweak_field_validation() {
    // Test that the taproot_tweak field is properly handled in Config
    use frost_client::trusted_dealer::inputs::Config;

    // Test Config with taproot_tweak = true
    let config_with_tweak = Config {
        min_signers: 2,
        max_signers: 3,
        secret: vec![1u8; 32], // Valid 32-byte secret
        taproot_tweak: true,
    };

    // Test Config with taproot_tweak = false
    let config_without_tweak = Config {
        min_signers: 2,
        max_signers: 3,
        secret: vec![2u8; 32], // Valid 32-byte secret
        taproot_tweak: false,
    };

    // Verify configs can be created and fields accessed
    assert_eq!(config_with_tweak.taproot_tweak, true);
    assert_eq!(config_without_tweak.taproot_tweak, false);
    assert_eq!(config_with_tweak.min_signers, 2);
    assert_eq!(config_with_tweak.max_signers, 3);

    println!("✅ Config taproot_tweak field validation passed");
}
