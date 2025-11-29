use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{H160, Bytes};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    // Test on USDC - a known clean contract
    let address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    println!("🔍 COMPREHENSIVE ANALYZER CHECK: USDC");
    println!("{}", "=".repeat(80));
    
    let addr = H160::from_str(address).unwrap();
    let bytecode: Bytes = provider.get_code(addr, None).await?;
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(bytecode.to_vec());
    let result = analyzer.analyze();
    
    println!("\n📊 ALL ANALYZER RESULTS:");
    println!("{}", "-".repeat(80));
    
    // Foundational
    println!("\n🔴 FOUNDATIONAL VULNERABILITIES:");
    println!("  Reentrancy: {}", result.reentrancy_vulnerabilities.len());
    println!("  Integer Safety: {}", result.integer_vulnerabilities.len());
    
    // DeFi & Protocol
    println!("\n🟡 DEFI & PROTOCOL VULNERABILITIES:");
    println!("  Economic Attacks: {}", result.economic_vulnerabilities.len());
    println!("  Upgrade/Proxy: {}", result.upgrade_vulnerabilities.len());
    println!("  Sandwich Attacks: {}", result.sandwich_vulnerabilities.len());
    println!("  Time Manipulation: {}", result.time_vulnerabilities.len());
    println!("  Cross-Contract: {}", result.cross_contract_vulnerabilities.len());
    
    // Comprehensive Security
    println!("\n🟠 COMPREHENSIVE SECURITY:");
    println!("  Bridge Security: {}", result.bridge_vulnerabilities.len());
    println!("  Protocol Dependencies: {}", result.protocol_dependency_vulnerabilities.len());
    println!("  DeFi Primitives: {}", result.defi_primitive_vulnerabilities.len());
    
    // Advanced Cross-Contract
    println!("\n🟣 ADVANCED CROSS-CONTRACT:");
    println!("  State Manipulation: {}", result.state_manipulation_vulnerabilities.len());
    println!("  MEV Attack Chains: {}", result.mev_attack_vulnerabilities.len());
    
    // Advanced Security
    println!("\n🔵 ADVANCED SECURITY ANALYSIS:");
    println!("  Governance Attacks: {}", result.governance_vulnerabilities.len());
    println!("  Oracle Infrastructure: {}", result.oracle_infrastructure_vulnerabilities.len());
    println!("  LP Economic Attacks: {}", result.lp_economic_vulnerabilities.len());
    println!("  Black Swan Events: {}", result.black_swan_vulnerabilities.len());
    println!("  Multi-Vector Attacks: {}", result.multi_vector_vulnerabilities.len());
    println!("  AI-Detected Patterns: {}", result.ai_detected_vulnerabilities.len());
    println!("  Infrastructure Risks: {}", result.infrastructure_vulnerabilities.len());
    
    // Latest Detectors
    println!("\n🟢 LATEST DETECTION MODULES:");
    println!("  Atomic Composability: {}", result.atomic_composability_vulnerabilities.len());
    println!("  Protocol Integration: {}", result.protocol_integration_vulnerabilities.len());
    println!("  Advanced MEV: {}", result.advanced_mev_vulnerabilities.len());
    println!("  Gas Economics: {}", result.gas_economic_vulnerabilities.len());
    println!("  Flash Loan Exploits: {}", result.flash_loan_vulnerabilities.len());
    println!("  Data Integrity: {}", result.data_integrity_vulnerabilities.len());
    
    println!("\n{}", "=".repeat(80));
    println!("📈 TOTAL VULNERABILITIES: {}", result.total_vulnerabilities);
    println!("🎯 ANALYSIS CONFIDENCE: {:.1}%", result.analysis_confidence * 100.0);
    println!("⏱️  ANALYSIS TIME: {}ms", result.coverage_metrics.analysis_duration_ms);
    println!("🔧 MODULES RUN: {}", result.coverage_metrics.analysis_modules_run);
    
    // Show samples from each category that found something
    if !result.governance_vulnerabilities.is_empty() {
        println!("\n🔍 GOVERNANCE SAMPLES:");
        for (i, v) in result.governance_vulnerabilities.iter().take(3).enumerate() {
            println!("  {}. {:?} - Severity: {:?}", i+1, v.attack_type, v.severity);
        }
    }
    
    if !result.flash_loan_vulnerabilities.is_empty() {
        println!("\n🔍 FLASH LOAN SAMPLES:");
        for (i, v) in result.flash_loan_vulnerabilities.iter().take(3).enumerate() {
            println!("  {}. Type: {:?} - Severity: {:?}", i+1, v.attack_type, v.severity);
        }
    }
    
    if !result.advanced_mev_vulnerabilities.is_empty() {
        println!("\n🔍 ADVANCED MEV SAMPLES:");
        for (i, v) in result.advanced_mev_vulnerabilities.iter().take(3).enumerate() {
            println!("  {}. {:?} - Confidence: {:.0}%", i+1, v.attack_type, v.confidence * 100.0);
        }
    }
    
    Ok(())
}
