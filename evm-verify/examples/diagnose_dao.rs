// Diagnose what full analyzer finds on The DAO
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{Address, Bytes};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 THE DAO - FULL ANALYZER DIAGNOSIS\n");
    
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let dao = Address::from_str("0xbb9bc244d798123fde783fcc1c72d3bb8c189413")?;
    let code: Bytes = provider.get_code(dao, None).await?;
    
    println!("Analyzing The DAO (known reentrancy vulnerability)...\n");
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let result = analyzer.analyze();
    
    println!("📊 TOTAL FINDINGS: {}\n", result.total_vulnerabilities);
    
    // Check all vulnerability types
    println!("🔍 Breakdown by Category:\n");
    
    macro_rules! print_vulns {
        ($name:expr, $field:expr) => {
            if !$field.is_empty() {
                println!("{}: {} findings", $name, $field.len());
            }
        };
    }
    
    // CRITICAL: Check foundational vulnerabilities FIRST
    if !result.reentrancy_vulnerabilities.is_empty() {
        println!("🚨 REENTRANCY: {} findings", result.reentrancy_vulnerabilities.len());
        for (i, v) in result.reentrancy_vulnerabilities.iter().take(3).enumerate() {
            println!("   {}. PC: {}, Opcode: 0x{:02X}, Severity: {:?}, Confidence: {:.2}",
                     i+1, v.pc, v.call_opcode, v.severity, v.confidence);
            println!("      {}", v.description);
        }
        println!();
    } else {
        println!("❌ REENTRANCY: 0 findings (PROBLEM - The DAO had reentrancy!)\n");
    }
    
    if !result.integer_vulnerabilities.is_empty() {
        println!("INTEGER OVERFLOW/UNDERFLOW: {} findings", result.integer_vulnerabilities.len());
        for (i, v) in result.integer_vulnerabilities.iter().take(3).enumerate() {
            println!("   {}. PC: {}, Operation: {:?}, Confidence: {:.2}",
                     i+1, v.pc, v.operation, v.confidence);
        }
        println!();
    }
    
    print_vulns!("Economic", result.economic_vulnerabilities);
    if !result.economic_vulnerabilities.is_empty() {
        for (i, v) in result.economic_vulnerabilities.iter().take(3).enumerate() {
            println!("   {}. Type: {:?}, Confidence: {:.2}, Severity: {:?}",
                     i+1, v.attack_type, v.detection_confidence, v.severity);
        }
        println!();
    }
    
    print_vulns!("Upgrade/Proxy", result.upgrade_vulnerabilities);
    print_vulns!("Sandwich", result.sandwich_vulnerabilities);
    print_vulns!("Time-based", result.time_vulnerabilities);
    print_vulns!("Cross-Contract", result.cross_contract_vulnerabilities);
    print_vulns!("Bridge", result.bridge_vulnerabilities);
    print_vulns!("Protocol Dependency", result.protocol_dependency_vulnerabilities);
    print_vulns!("DeFi Primitive", result.defi_primitive_vulnerabilities);
    print_vulns!("State Manipulation", result.state_manipulation_vulnerabilities);
    print_vulns!("MEV Attack", result.mev_attack_vulnerabilities);
    print_vulns!("Governance", result.governance_vulnerabilities);
    print_vulns!("Oracle Infrastructure", result.oracle_infrastructure_vulnerabilities);
    print_vulns!("LP Economic", result.lp_economic_vulnerabilities);
    print_vulns!("Black Swan", result.black_swan_vulnerabilities);
    print_vulns!("Multi-Vector", result.multi_vector_vulnerabilities);
    print_vulns!("AI Detected", result.ai_detected_vulnerabilities);
    print_vulns!("Infrastructure", result.infrastructure_vulnerabilities);
    print_vulns!("Atomic Composability", result.atomic_composability_vulnerabilities);
    print_vulns!("Protocol Integration", result.protocol_integration_vulnerabilities);
    print_vulns!("Advanced MEV", result.advanced_mev_vulnerabilities);
    print_vulns!("Gas Economic", result.gas_economic_vulnerabilities);
    print_vulns!("Flash Loan", result.flash_loan_vulnerabilities);
    print_vulns!("Data Integrity", result.data_integrity_vulnerabilities);
    
    println!("💡 Expected: Should detect reentrancy vulnerability");
    println!("   The DAO had the famous reentrancy bug that drained $50M+");
    
    Ok(())
}
