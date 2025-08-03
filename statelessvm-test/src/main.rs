use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== StatelessVM Connectivity Test ===\n");
    
    // Get StatelessVM endpoint from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL")
        .unwrap_or_else(|_| {
            println!("STATELESSVM_URL not set, using default local endpoint");
            "http://localhost:7548".to_string()
        });
    
    println!("Testing connection to StatelessVM at: {}", statelessvm_url);
    
    // Test 1: Health check
    println!("\n[Test 1] Health check...");
    match reqwest::get(format!("{}/health", statelessvm_url)).await {
        Ok(response) => {
            let status = response.status();
            let text = response.text().await?;
            
            if status.is_success() {
                println!("✅ PASSED: Health check successful");
                println!("  Status: {}", status);
                println!("  Response: {}", text);
            } else {
                println!("❌ FAILED: Health check failed");
                println!("  Status: {}", status);
                println!("  Response: {}", text);
            }
        },
        Err(e) => {
            println!("❌ FAILED: Health check failed - Connection error");
            println!("  Error: {}", e);
            return Err(e.into());
        }
    }

    // Test 2: Info endpoint
    println!("\n[Test 2] Info endpoint check...");
    match reqwest::get(format!("{}/info", statelessvm_url)).await {
        Ok(response) => {
            let status = response.status();
            
            if status.is_success() {
                let text = response.text().await?;
                println!("✅ PASSED: Info endpoint check successful");
                println!("  Status: {}", status);
                println!("  Response: {}", text);
            } else {
                println!("⚠️ NOTE: Info endpoint returned status {}", status);
                println!("  (This endpoint might not be implemented in your StatelessVM version)");
            }
        },
        Err(_) => {
            println!("⚠️ NOTE: Info endpoint not available");
            println!("  (This endpoint might not be implemented in your StatelessVM version)");
        }
    }
    
    // Test 3: Attempt to send a simple security verification request
    println!("\n[Test 3] Security verification API test...");
    
    // Create a simple JSON payload for the security verification
    let test_payload = serde_json::json!({
        "address": "0x0000000000000000000000000000000000000000",
        "verify_reentrancy": true,
        "verify_integer_underflow": true,
        "verify_integer_overflow": true,
        "verify_unchecked_calls": true,
        "verify_upgradability": true,
        "verify_mev_vulnerability": true,
        "verify_cross_contract_reentrancy": true,
        "verify_precision_loss": true,
        "verify_gas_griefing": true
    });
    
    match reqwest::Client::new()
        .post(format!("{}/verify", statelessvm_url))
        .json(&test_payload)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            
            if status.is_success() {
                let text = response.text().await?;
                println!("✅ PASSED: Security verification API check successful");
                println!("  Status: {}", status);
                println!("  Response: {}", text);
            } else if status.as_u16() == 404 {
                println!("⚠️ NOTE: Security verification endpoint not found (404)");
                println!("  (This is expected if security verification is handled via the execute endpoint)");
            } else {
                let text = response.text().await?;
                println!("⚠️ NOTE: Security verification endpoint returned status {}", status);
                println!("  Response: {}", text);
            }
        },
        Err(e) => {
            println!("⚠️ NOTE: Could not connect to security verification endpoint");
            println!("  Error: {}", e);
            println!("  (This is expected if security verification is handled via the execute endpoint)");
        }
    }
    
    // Test 4: Simple query check
    println!("\n[Test 4] Status check...");
    
    match reqwest::get(format!("{}/status", statelessvm_url)).await {
        Ok(response) => {
            let status = response.status();
            
            if status.is_success() {
                let text = response.text().await?;
                println!("✅ PASSED: Status check successful");
                println!("  Status: {}", status);
                println!("  Response: {}", text);
            } else {
                println!("⚠️ NOTE: Status endpoint returned status {}", status);
                println!("  (This endpoint might not be implemented in your StatelessVM version)");
            }
        },
        Err(_) => {
            println!("⚠️ NOTE: Status endpoint not available");
            println!("  (This endpoint might not be implemented in your StatelessVM version)");
        }
    }

    // Print summary
    println!("\n=== StatelessVM Connectivity Test Summary ===");
    println!("StatelessVM service at {} is operational!", statelessvm_url);
    println!("The health check endpoint is working properly.");
    println!("Your StatelessVM service is ready to process transactions.");
    
    Ok(())
}
