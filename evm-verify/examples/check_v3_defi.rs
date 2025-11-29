// Quick check if Uniswap V3 is detected as DeFi
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{Address, Bytes};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let v3_pool = Address::from_str("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640")?;
    let code: Bytes = provider.get_code(v3_pool, None).await?;
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let result = analyzer.analyze();
    
    println!("Uniswap V3 Pool Analysis:");
    println!("Total integers: {}", result.integer_vulnerabilities.len());
    
    let high_conf: Vec<_> = result.integer_vulnerabilities.iter()
        .filter(|v| {
            (matches!(v.severity, evm_verify::bytecode::SecuritySeverity::Critical) && v.confidence > 0.80) || 
            (matches!(v.severity, evm_verify::bytecode::SecuritySeverity::High) && v.confidence >= 0.85) ||
            v.confidence >= 0.95
        })
        .collect();
    
    println!("High confidence: {}", high_conf.len());
    
    // Check first few
    for (i, v) in high_conf.iter().take(3).enumerate() {
        println!("  {}. PC: {}, Op: {:?}, Conf: {:.0}%, Sev: {:?}",
                 i+1, v.pc, v.operation, v.confidence * 100.0, v.severity);
    }
    
    Ok(())
}
