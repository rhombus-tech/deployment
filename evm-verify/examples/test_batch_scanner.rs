use evm_verify::scanner::{BatchScanner, Priority};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Testing Batch Scanner with Priority Queue");
    println!("{}", "=".repeat(80));
    
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    
    let scanner = BatchScanner::new(&rpc_url, 5).await?;
    
    // Queue contracts with different priorities
    println!("\n📋 Queueing contracts...");
    
    scanner.queue_batch(vec![
        ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(), Priority::High, Some(10000000.0)), // USDC - High TVL
        ("0xc5d105e63711398af9bbff092d4b6769c82f793d".to_string(), Priority::Critical, None),        // BeautyChain - Critical
        ("0x5d3a536e4d6dbd6114cc1ead35777bab948e3643".to_string(), Priority::Medium, Some(500000.0)), // Compound - Medium
        ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(), Priority::Low, None),             // WETH - Low
    ]).await;
    
    println!("✅ Queued {} contracts", scanner.queue_size().await);
    
    // Process batch
    println!("\n⚡ Processing batch (max 3 concurrent)...");
    let start = std::time::Instant::now();
    
    let results = scanner.process_batch(3).await;
    
    println!("✅ Processed {} contracts in {} ms", 
             results.len(), start.elapsed().as_millis());
    
    // Show results
    println!("\n📊 Results:");
    for (address, result) in results {
        match result {
            Ok(analysis) => {
                let short_addr = &address[..10];
                println!("  ✓ {} - {} findings", short_addr, analysis.total_vulnerabilities);
            }
            Err(e) => {
                println!("  ✗ {} - Error: {}", &address[..10], e);
            }
        }
    }
    
    println!("\n📈 Queue Status:");
    println!("  Remaining: {}", scanner.queue_size().await);
    println!("  In Progress: {}", scanner.in_progress_count().await);
    
    Ok(())
}
