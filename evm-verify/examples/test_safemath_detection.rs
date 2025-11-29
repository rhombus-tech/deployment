// Test SafeMath detection on USDC
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{Address, Bytes};
use std::str::FromStr;
use evm_verify::analysis::integer_safety_detector::IntegerSafetyDetector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    println!("Testing SafeMath Detection\n");
    
    // Test USDC
    let usdc = Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")?;
    let code: Bytes = provider.get_code(usdc, None).await?;
    let detector = IntegerSafetyDetector::new(code.to_vec());
    let vulnerabilities = detector.detect_vulnerabilities();
    
    println!("USDC:");
    println!("  Total integer issues: {}", vulnerabilities.len());
    println!("  (If 0 or very low, SafeMath was detected correctly)");
    
    // Test BeautyChain (should have issues)
    let beauty = Address::from_str("0xc5d105e63711398af9bbff092d4b6769c82f793d")?;
    let code2: Bytes = provider.get_code(beauty, None).await?;
    let detector2 = IntegerSafetyDetector::new(code2.to_vec());
    let vulnerabilities2 = detector2.detect_vulnerabilities();
    
    println!("\nBeautyChain:");
    println!("  Total integer issues: {}", vulnerabilities2.len());
    println!("  (Should have many issues - vulnerable contract)");
    
    Ok(())
}
