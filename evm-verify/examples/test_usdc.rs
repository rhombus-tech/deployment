use ethers::providers::{Provider, Http, Middleware};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use evm_verify::bytecode::SecuritySeverity;
use ethers::types::Address;

#[tokio::main]
async fn main() {
    let provider = Provider::<Http>::try_from("https://ethereum.publicnode.com").unwrap();
    let addr = Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(); // USDC
    let code = provider.get_code(addr, None).await.unwrap();
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let mut result = analyzer.analyze();
    
    println!("USDC Contract Test:");
    println!("Before: {} integer vulnerabilities", result.integer_vulnerabilities.len());
    
    let high_conf_integers: Vec<_> = result.integer_vulnerabilities.iter()
        .filter(|v| v.confidence > 0.80)
        .cloned()
        .collect();
    
    println!("With >80% confidence: {}", high_conf_integers.len());
    
    if high_conf_integers.len() >= 10 {
        println!("❌ WOULD FLAG (10+ high-confidence issues)");
    } else {
        println!("✅ WOULD NOT FLAG (< 10 high-confidence issues)");
    }
}
