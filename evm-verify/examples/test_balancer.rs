use ethers::providers::{Provider, Http, Middleware};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use evm_verify::bytecode::SecuritySeverity;
use ethers::types::Address;

#[tokio::main]
async fn main() {
    println!("🔍 Testing Balancer V2 Vault (Recent $128M Exploit)");
    println!("Address: 0xBA12222222228d8Ba445958a75a0704d566BF2C8\n");
    
    let provider = Provider::<Http>::try_from("https://ethereum.publicnode.com").unwrap();
    let addr = Address::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8").unwrap();
    
    println!("Fetching bytecode...");
    let code = provider.get_code(addr, None).await.unwrap();
    println!("Bytecode size: {} bytes\n", code.len());
    
    println!("Running comprehensive analysis...");
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let mut result = analyzer.analyze();
    
    println!("\n=== BEFORE FILTERING ===");
    println!("Total vulnerabilities: {}", result.total_vulnerabilities);
    println!("  Precision/Rounding: {}", result.precision_vulnerabilities.len());
    println!("  Integer: {}", result.integer_vulnerabilities.len());
    println!("  Economic: {}", result.economic_vulnerabilities.len());
    println!("  Reentrancy: {}", result.reentrancy_vulnerabilities.len());
    
    // Apply conservative filtering (same as live scanner)
    let high_conf_integers: Vec<_> = result.integer_vulnerabilities.iter()
        .filter(|v| v.confidence > 0.80)
        .cloned()
        .collect();
    
    if high_conf_integers.len() >= 10 {
        result.integer_vulnerabilities = high_conf_integers;
    } else {
        result.integer_vulnerabilities.retain(|v| {
            (matches!(v.severity, SecuritySeverity::Critical) && v.confidence > 0.85) ||
            v.confidence > 0.95
        });
    }
    
    result.precision_vulnerabilities.retain(|v| {
        v.detection_confidence > 0.75 &&
        (matches!(v.severity, SecuritySeverity::Critical | SecuritySeverity::High))
    });
    
    result.economic_vulnerabilities.retain(|v| {
        v.detection_confidence > 0.80 &&
        (matches!(v.severity, SecuritySeverity::Critical | SecuritySeverity::High))
    });
    
    let total_after = result.precision_vulnerabilities.len() +
                     result.integer_vulnerabilities.len() +
                     result.economic_vulnerabilities.len();
    
    println!("\n=== AFTER CONSERVATIVE FILTERING ===");
    println!("Total vulnerabilities: {}", total_after);
    println!("  Precision/Rounding: {}", result.precision_vulnerabilities.len());
    println!("  Integer: {}", result.integer_vulnerabilities.len());
    println!("  Economic: {}", result.economic_vulnerabilities.len());
    
    println!("\n=== VERDICT ===");
    if total_after > 0 {
        println!("🔴 WOULD FLAG AS VULNERABLE");
        println!("   Risk Level: CRITICAL");
    } else {
        println!("✅ Would not flag (clean)");
    }
}
