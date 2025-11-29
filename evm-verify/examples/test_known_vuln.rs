use ethers::providers::{Provider, Http, Middleware};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use ethers::types::Address;

#[tokio::main]
async fn main() {
    let provider = Provider::<Http>::try_from("https://ethereum.publicnode.com").unwrap();
    let addr = Address::from_str("0x0e87bF5286C4091e0eeb7814D802115dFBb4c4cd").unwrap();
    let code = provider.get_code(addr, None).await.unwrap();
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let result = analyzer.analyze();
    
    println!("Known vulnerable contract (0x0e87bF52...):");
    println!("  Total: {}", result.total_vulnerabilities);
    println!("  Reentrancy: {}", result.reentrancy_vulnerabilities.len());
    println!("  Integer: {}", result.integer_vulnerabilities.len());
}
