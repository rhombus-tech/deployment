use ethers::providers::{Provider, Http, Middleware};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use evm_verify::bytecode::SecuritySeverity;
use ethers::types::Address;

#[tokio::main]
async fn main() {
    let provider = Provider::<Http>::try_from("https://ethereum.publicnode.com").unwrap();
    let addr = Address::from_str("0x0e87bF5286C4091e0eeb7814D802115dFBb4c4cd").unwrap();
    let code = provider.get_code(addr, None).await.unwrap();
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let mut result = analyzer.analyze();
    
    println!("=== BEFORE FILTERING ===");
    println!("Total: {}", result.total_vulnerabilities);
    println!("Reentrancy: {}", result.reentrancy_vulnerabilities.len());
    println!("Integer: {}", result.integer_vulnerabilities.len());
    println!("Economic: {}", result.economic_vulnerabilities.len());
    
    // Apply the same conservative filtering as the scanner
    result.reentrancy_vulnerabilities.retain(|v| {
        matches!(v.severity, SecuritySeverity::Critical) ||
        (matches!(v.severity, SecuritySeverity::High) && v.confidence > 0.85)
    });
    
    result.integer_vulnerabilities.retain(|v| {
        (matches!(v.severity, SecuritySeverity::Critical) && v.confidence > 0.85) ||
        v.confidence > 0.95
    });
    
    result.economic_vulnerabilities.retain(|v| {
        v.detection_confidence > 0.80 &&
        (matches!(v.severity, SecuritySeverity::Critical | SecuritySeverity::High))
    });
    
    // Recalculate
    result.total_vulnerabilities = 
        result.reentrancy_vulnerabilities.len() as u32 +
        result.integer_vulnerabilities.len() as u32 +
        result.economic_vulnerabilities.len() as u32;
    
    println!("\n=== AFTER CONSERVATIVE FILTERING ===");
    println!("Total: {}", result.total_vulnerabilities);
    println!("Reentrancy: {}", result.reentrancy_vulnerabilities.len());
    println!("Integer: {}", result.integer_vulnerabilities.len());
    println!("Economic: {}", result.economic_vulnerabilities.len());
    
    if result.total_vulnerabilities > 0 {
        println!("\n✅ WOULD FLAG AS VULNERABLE");
    } else {
        println!("\n❌ WOULD NOT FLAG");
    }
}
