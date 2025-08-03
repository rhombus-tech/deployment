use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

/// Example client demonstrating real-time zkEVM processing API usage
/// 
/// This example shows how to:
/// 1. Start real-time processing with Ethereum WebSocket connection
/// 2. Monitor processing status and statistics
/// 3. Stop real-time processing when needed
///
/// Usage: 
/// ```bash
/// # Start the zkEVM server first:
/// cargo run --bin stateless-vm-server
/// 
/// # In another terminal, run this example:
/// cargo run --example realtime_client
/// ```

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let base_url = "http://localhost:8080";
    
    println!("🚀 zkEVM Real-Time Processing Demo");
    println!("================================");
    
    // 1. Check server health
    println!("\n1. Checking server health...");
    let health_response = client
        .get(&format!("{}/health", base_url))
        .send()
        .await?;
    
    if health_response.status().is_success() {
        println!("✅ Server is healthy and ready");
    } else {
        println!("❌ Server health check failed");
        return Ok(());
    }
    
    // 2. Start real-time processing
    println!("\n2. Starting real-time zkEVM processing...");
    let start_request = json!({
        "websocket_url": "wss://eth-mainnet.alchemyapi.io/v2/your-api-key",
        "processing_mode": "RealTime",
        "target_latency_seconds": 60,
        "worker_count": 4
    });
    
    let start_response = client
        .post(&format!("{}/api/v1/realtime/start", base_url))
        .json(&start_request)
        .send()
        .await?;
    
    if start_response.status().is_success() {
        let response_json: serde_json::Value = start_response.json().await?;
        println!("✅ Real-time processing started successfully");
        println!("   Response: {}", response_json);
    } else {
        let error_text = start_response.text().await?;
        println!("❌ Failed to start real-time processing: {}", error_text);
        return Ok(());
    }
    
    // 3. Monitor processing status for 30 seconds
    println!("\n3. Monitoring real-time processing status...");
    for i in 1..=6 {
        sleep(Duration::from_secs(5)).await;
        
        let status_response = client
            .get(&format!("{}/api/v1/realtime/status", base_url))
            .send()
            .await?;
        
        if status_response.status().is_success() {
            let status_json: serde_json::Value = status_response.json().await?;
            
            println!("📊 Status Check #{}: {}", i, format_status(&status_json));
            
            // Show key metrics
            if let Some(blocks_processed) = status_json.get("blocks_processed") {
                println!("   📦 Blocks Processed: {}", blocks_processed);
            }
            if let Some(queue_size) = status_json.get("queue_size") {
                println!("   ⏳ Queue Size: {}", queue_size);
            }
            if let Some(avg_time) = status_json.get("avg_processing_time_ms") {
                println!("   ⚡ Avg Processing Time: {}ms", avg_time);
            }
            if let Some(current_block) = status_json.get("current_block_number") {
                println!("   🔢 Current Block: {}", current_block);
            }
        } else {
            println!("❌ Failed to get status");
        }
    }
    
    // 4. Stop real-time processing
    println!("\n4. Stopping real-time processing...");
    let stop_response = client
        .post(&format!("{}/api/v1/realtime/stop", base_url))
        .send()
        .await?;
    
    if stop_response.status().is_success() {
        let response_json: serde_json::Value = stop_response.json().await?;
        println!("✅ Real-time processing stopped successfully");
        println!("   Response: {}", response_json);
    } else {
        let error_text = stop_response.text().await?;
        println!("❌ Failed to stop real-time processing: {}", error_text);
    }
    
    // 5. Final status check
    println!("\n5. Final status check...");
    let final_status_response = client
        .get(&format!("{}/api/v1/realtime/status", base_url))
        .send()
        .await?;
    
    if final_status_response.status().is_success() {
        let status_json: serde_json::Value = final_status_response.json().await?;
        println!("📊 Final Status: {}", format_status(&status_json));
    }
    
    println!("\n🎉 Real-time processing demo completed!");
    println!("\n💡 Next Steps:");
    println!("   • Replace websocket_url with your Alchemy/Infura endpoint");
    println!("   • Adjust target_latency_seconds and worker_count for your needs");
    println!("   • Monitor the /api/v1/realtime/status endpoint for production metrics");
    println!("   • Use ProcessingMode::Recent for catch-up processing");
    println!("   • Use ProcessingMode::Historical for full blockchain analysis");
    
    Ok(())
}

fn format_status(status: &serde_json::Value) -> String {
    let is_running = status.get("is_running")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    
    let processing_mode = status.get("processing_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    
    if is_running {
        format!("🟢 Running (Mode: {})", processing_mode)
    } else {
        let error = status.get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("No error");
        format!("🔴 Stopped (Error: {})", error)
    }
}
