// Diagnose Uniswap V2 false positives
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{Address, Bytes};
use std::str::FromStr;
use evm_verify::analysis::conservative_config::analyze_conservative;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 UNISWAP V2 ROUTER DIAGNOSIS\n");
    
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let uniswap = Address::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")?;
    let code: Bytes = provider.get_code(uniswap, None).await?;
    
    let result = analyze_conservative(&code.to_vec());
    
    println!("Total: {}", result.total_vulnerabilities);
    println!("Critical: {}, High: {}\n", result.critical_count, result.high_count);
    
    println!("🔍 Detailed Breakdown:\n");
    
    for (i, v) in result.sandwich_vulnerabilities.iter().enumerate() {
        println!("Sandwich #{}: {:?} - {:?}", i+1, v.attack_type, v.severity);
        println!("  Description: {}", v.description);
        println!();
    }
    
    for (i, v) in result.economic_vulnerabilities.iter().enumerate() {
        println!("Economic #{}: {:?} - {:?} (conf: {:.2})", 
                 i+1, v.attack_type, v.severity, v.detection_confidence);
        println!("  Description: {}", v.description);
        println!();
    }
    
    Ok(())
}
