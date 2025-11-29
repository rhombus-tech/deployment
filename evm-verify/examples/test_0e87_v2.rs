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
    println!("Integer: {}", result.integer_vulnerabilities.len());
    
    // NEW FILTERING: Systematic pattern (10+ with 80%+ confidence)
    let high_conf_integers: Vec<_> = result.integer_vulnerabilities.iter()
        .filter(|v| v.confidence > 0.80)
        .cloned()
        .collect();
    
    println!("\nInteger vulns with >80% confidence: {}", high_conf_integers.len());
    
    if high_conf_integers.len() >= 10 {
        result.integer_vulnerabilities = high_conf_integers;
        println!("✅ Keeping {} systematic integer vulnerabilities", result.integer_vulnerabilities.len());
    } else {
        result.integer_vulnerabilities.retain(|v| {
            (matches!(v.severity, SecuritySeverity::Critical) && v.confidence > 0.85) ||
            v.confidence > 0.95
        });
    }
    
    println!("\n=== AFTER CONSERVATIVE FILTERING ===");
    println!("Integer: {}", result.integer_vulnerabilities.len());
    
    if result.integer_vulnerabilities.len() > 0 {
        println!("\n🔴 WOULD FLAG AS VULNERABLE");
    } else {
        println!("\n❌ WOULD NOT FLAG");
    }
}
