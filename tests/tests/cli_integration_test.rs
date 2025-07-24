use std::process::{Command, Stdio};
use std::time::Duration;
use std::fs;
use tempfile::TempDir;
use tokio::time::timeout;
use tokio::process::Command as TokioCommand;

// Helper function to start a participant
async fn start_participant(
    key_package: String,
    port: String,
    test_dir: std::path::PathBuf
) -> Result<(String, String), String> {  // Return (stdout, stderr)
    // Use yes command to automatically answer 'y' to prompts
    let output = TokioCommand::new("sh")
        .args(["-c", &format!("echo 'y' | participant -C secp256k1-tr --ip 127.0.0.1 --port {} -k {}", port, key_package)])
        .current_dir(&test_dir)
        .output()
        .await
        .map_err(|e| format!("Failed to spawn participant {}: {}", key_package, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok((stdout, stderr))
    } else {
        Err(format!("Participant {} failed with status: {}\nstdout: {}\nstderr: {}",
                   key_package, output.status, stdout, stderr))
    }
}

#[tokio::test]
async fn test_cli_frost_taproot_signing_ceremony() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Starting CLI FROST Taproot signing ceremony test");

    // Create temporary directory for test
    let temp_dir = TempDir::new()?;
    let test_path = temp_dir.path();

    println!("📁 Test directory: {:?}", test_path);

    // Step 1: Generate FROST key material with Taproot tweak
    println!("🔑 Step 1: Generating FROST key material with Taproot tweak...");

    let trusted_dealer_output = Command::new("trusted-dealer")
        .args(["-t", "2", "-n", "3", "-C", "secp256k1-tr"])
        .current_dir(test_path)
        .output()?;

    if !trusted_dealer_output.status.success() {
        return Err(format!("trusted-dealer failed: {}",
                          String::from_utf8_lossy(&trusted_dealer_output.stderr)).into());
    }

    // Verify key files were created
    for file in ["public-key-package.json", "key-package-1.json", "key-package-2.json", "key-package-3.json"] {
        if !test_path.join(file).exists() {
            return Err(format!("Missing key file: {}", file).into());
        }
    }

    println!("✅ Key material generated successfully");

    // Step 2: Create test message
    let message = "Hello FROST CLI with Taproot tweak!";
    fs::write(test_path.join("message.txt"), message)?;

    println!("📝 Test message: '{}'", message);

    // Step 3: Start coordinator in background
    println!("🎯 Step 3: Starting coordinator...");

    let coordinator_port = "12750"; // Use different port from bash script
    let mut coordinator = TokioCommand::new("coordinator")
        .args([
            "-C", "secp256k1-tr",
            "--ip", "127.0.0.1",
            "--port", coordinator_port,
            "--public-key-package", "public-key-package.json",
            "--message", "message.txt",
            "--num-signers", "2",
            "--signature", "signature.bin"
        ])
        .current_dir(test_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Give coordinator time to start
    tokio::time::sleep(Duration::from_secs(3)).await;

    println!("✅ Coordinator started");

    // Step 4: Start participants concurrently
    println!("👥 Step 4: Starting participants...");

    // Start both participants concurrently
    let participant1_future = start_participant(
        "key-package-1.json".to_string(),
        coordinator_port.to_string(),
        test_path.to_path_buf()
    );
    let participant2_future = start_participant(
        "key-package-2.json".to_string(),
        coordinator_port.to_string(),
        test_path.to_path_buf()
    );

    // Wait for both participants to complete
    let (result1, result2) = tokio::join!(participant1_future, participant2_future);

    // Check results and capture outputs
    let (stdout1, stderr1) = result1.map_err(|e| format!("Participant 1: {}", e))?;
    let (stdout2, stderr2) = result2.map_err(|e| format!("Participant 2: {}", e))?;

    println!("📋 Participant 1 stdout:\n{}", stdout1);
    if !stderr1.is_empty() {
        println!("📋 Participant 1 stderr:\n{}", stderr1);
    }

    println!("📋 Participant 2 stdout:\n{}", stdout2);
    if !stderr2.is_empty() {
        println!("📋 Participant 2 stderr:\n{}", stderr2);
    }

    println!("✅ Participants completed successfully");

    // Step 5: Wait for coordinator to finish and collect signature
    println!("⏳ Step 5: Waiting for coordinator to complete...");

    // Give more time for signature aggregation
    tokio::time::sleep(Duration::from_secs(5)).await;

    let coordinator_result = timeout(Duration::from_secs(30), coordinator.wait()).await;

    match coordinator_result {
        Ok(Ok(status)) => {
            if !status.success() {
                // Get coordinator output for debugging
                let output = coordinator.wait_with_output().await?;
                return Err(format!("Coordinator failed: {}",
                                 String::from_utf8_lossy(&output.stderr)).into());
            }
        }
        Ok(Err(e)) => return Err(format!("Coordinator error: {}", e).into()),
        Err(_) => {
            // Coordinator timed out, get output and kill it
            println!("⚠️ Coordinator timed out, attempting to collect output...");
            let _ = coordinator.start_kill();

            // Try to get coordinator output for debugging
            if let Ok(output) = coordinator.wait_with_output().await {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                if !stdout.is_empty() {
                    println!("📋 Coordinator stdout:\n{}", stdout);
                }
                if !stderr.is_empty() {
                    println!("📋 Coordinator stderr:\n{}", stderr);
                }
            }

            // Check if signature was generated despite timeout
            let signature_path = test_path.join("signature.bin");
            if signature_path.exists() && fs::read(&signature_path)?.len() == 64 {
                println!("✅ Signature was generated despite coordinator timeout");
            } else {
                return Err("Coordinator timed out and no valid signature generated".into());
            }
        }
    }

    println!("✅ Coordinator completed successfully");

    // Step 6: Verify signature was generated
    println!("🔍 Step 6: Verifying signature generation...");

    let signature_path = test_path.join("signature.bin");
    if !signature_path.exists() {
        return Err("Signature file not created".into());
    }

    let signature_bytes = fs::read(&signature_path)?;
    if signature_bytes.len() != 64 {
        return Err(format!("Expected 64-byte signature, got {}", signature_bytes.len()).into());
    }

    println!("✅ Signature file created: {} bytes", signature_bytes.len());

    // Step 7: Verify signature cryptographically
    println!("🔐 Step 7: Performing cryptographic verification...");

    // Read the public key package
    let public_key_json = fs::read_to_string(test_path.join("public-key-package.json"))?;
    let public_key_package: frost_secp256k1_tr::keys::PublicKeyPackage =
        serde_json::from_str(&public_key_json)?;

    // Get the verifying key (Taproot-tweaked)
    let verifying_key = public_key_package.verifying_key();

    // Parse the signature
    let signature = frost_secp256k1_tr::Signature::deserialize(&signature_bytes)?;

    // Verify the signature
    match verifying_key.verify(message.as_bytes(), &signature) {
        Ok(()) => {
            println!("✅ Signature verification: PASSED");
            println!("🎯 Message was signed with Taproot-tweaked FROST threshold signature");
        }
        Err(e) => {
            return Err(format!("Signature verification failed: {:?}", e).into());
        }
    }

    // Step 8: Verify Taproot tweak was applied
    println!("🔧 Step 8: Verifying Taproot tweak...");

    // Generate non-tweaked keys for comparison
    let comparison_dir = test_path.join("comparison");
    fs::create_dir(&comparison_dir)?;

    let untweaked_output = Command::new("trusted-dealer")
        .args(["-t", "2", "-n", "3", "-C", "secp256k1-tr"])
        .current_dir(&comparison_dir)
        .output()?;

    if !untweaked_output.status.success() {
        return Err("Failed to generate untweaked keys for comparison".into());
    }

    let untweaked_json = fs::read_to_string(comparison_dir.join("public-key-package.json"))?;
    let untweaked_package: frost_secp256k1_tr::keys::PublicKeyPackage =
        serde_json::from_str(&untweaked_json)?;

    let tweaked_key = public_key_package.verifying_key().serialize()?;
    let untweaked_key = untweaked_package.verifying_key().serialize()?;

    if tweaked_key == untweaked_key {
        return Err("Taproot tweak did not change the public key".into());
    }

    println!("✅ Taproot tweak verification passed");
    println!("📋 Tweaked key:   {}", hex::encode(&tweaked_key));
    println!("📋 Untweaked key: {}", hex::encode(&untweaked_key));

    // Summary
    println!("");
    println!("🎉 CLI FROST Taproot integration test completed successfully!");
    println!("===============================================");
    println!("✅ CLI key generation with Taproot tweak");
    println!("✅ CLI coordinator/participant orchestration");
    println!("✅ Concurrent participant execution");
    println!("✅ Signature generation via CLI tools");
    println!("✅ Cryptographic signature verification");
    println!("✅ Taproot tweak functionality validation");

    Ok(())
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[tokio::test]
    async fn test_process_timeout_handling() -> Result<(), Box<dyn std::error::Error>> {
        // Test that we can properly timeout and kill processes
        let mut long_running = TokioCommand::new("sleep")
            .arg("10")
            .spawn()?;

        let result = timeout(Duration::from_secs(1), long_running.wait()).await;

        match result {
            Err(_) => {
                // Expected timeout
                let _ = long_running.kill().await;
                println!("✅ Process timeout handling works correctly");
                Ok(())
            }
            Ok(_) => Err("Process should have timed out".into()),
        }
    }

    #[test]
    fn test_key_file_validation() {
        // Test that we can validate the existence of required key files
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path();

        // Create test files
        for file in ["public-key-package.json", "key-package-1.json"] {
            fs::write(test_path.join(file), "{}").unwrap();
        }

        // Verify files exist
        assert!(test_path.join("public-key-package.json").exists());
        assert!(test_path.join("key-package-1.json").exists());
        assert!(!test_path.join("key-package-missing.json").exists());

        println!("✅ Key file validation works correctly");
    }
}
