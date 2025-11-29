// Diagnose what the conservative analyzer is still flagging
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{Address, Bytes};
use std::str::FromStr;
use evm_verify::analysis::conservative_config::analyze_conservative;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 CONSERVATIVE ANALYZER DETAILED DIAGNOSIS\n");
    
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    // Test USDC (known safe)
    let usdc = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")?;
    let code: Bytes = provider.get_code(usdc, None).await?;
    
    println!("📦 USDC Token Contract");
    println!("========================\n");
    
    let result = analyze_conservative(&code.to_vec());
    
    println!("Total Vulnerabilities: {}", result.total_vulnerabilities);
    println!("Critical: {}", result.critical_count);
    println!("High: {}", result.high_count);
    println!();
    
    // Break down by type
    println!("🔍 Breakdown by Type:");
    println!();
    
    if !result.economic_vulnerabilities.is_empty() {
        println!("Economic: {}", result.economic_vulnerabilities.len());
        for v in &result.economic_vulnerabilities {
            println!("  - Type: {:?}, Confidence: {:.2}, Severity: {:?}", 
                     v.attack_type, v.detection_confidence, v.severity);
        }
        println!();
    }
    
    if !result.sandwich_vulnerabilities.is_empty() {
        println!("Sandwich: {}", result.sandwich_vulnerabilities.len());
        for v in &result.sandwich_vulnerabilities {
            println!("  - Type: {:?}, Severity: {:?}", v.attack_type, v.severity);
        }
        println!();
    }
    
    if !result.mev_attack_vulnerabilities.is_empty() {
        println!("MEV Attack: {}", result.mev_attack_vulnerabilities.len());
        println!();
    }
    
    if !result.flash_loan_vulnerabilities.is_empty() {
        println!("Flash Loan: {}", result.flash_loan_vulnerabilities.len());
        println!();
    }
    
    println!();
    println!("💡 Analysis:");
    println!("These are the vulnerabilities still flagged by conservative config.");
    println!("We need to determine which are legitimate security patterns vs false positives.");
    
    Ok(())
}
