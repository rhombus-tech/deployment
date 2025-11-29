// Diagnose why safe contracts are being flagged
// Usage: cargo run --example diagnose_false_positives

use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{Address, Bytes};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 DIAGNOSING FALSE POSITIVES");
    println!("==============================\n");
    
    // Analyze USDC (known safe, but flagged with 634 vulnerabilities)
    let usdc_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    println!("Analyzing USDC Token...");
    println!("Address: {}\n", usdc_address);
    
    // Fetch bytecode
    let addr = Address::from_str(usdc_address)?;
    let code: Bytes = provider.get_code(addr, None).await?;
    let bytecode = code.to_vec();
    
    // Analyze
    let analyzer = ComprehensiveSecurityAnalyzer::new(bytecode.clone());
    let result = analyzer.analyze();
    
    println!("📊 ANALYSIS RESULTS:\n");
    println!("Total Vulnerabilities: {}", result.total_vulnerabilities);
    println!("Critical: {}", result.security_summary.critical_count);
    println!("High: {}", result.security_summary.high_count);
    println!("Medium: {}", result.security_summary.medium_count);
    println!("Low: {}", result.security_summary.low_count);
    println!();
    
    // Count by type
    let mut type_counts: HashMap<&str, usize> = HashMap::new();
    
    println!("🔬 BREAKDOWN BY TYPE:\n");
    
    macro_rules! count_vulns {
        ($field:expr, $name:expr) => {
            if !$field.is_empty() {
                type_counts.insert($name, $field.len());
                println!("{}: {}", $name, $field.len());
            }
        };
    }
    
    count_vulns!(result.economic_vulnerabilities, "Economic");
    count_vulns!(result.upgrade_vulnerabilities, "Upgrade");
    count_vulns!(result.sandwich_vulnerabilities, "Sandwich");
    count_vulns!(result.time_vulnerabilities, "Time");
    count_vulns!(result.cross_contract_vulnerabilities, "Cross-Contract");
    count_vulns!(result.bridge_vulnerabilities, "Bridge");
    count_vulns!(result.protocol_dependency_vulnerabilities, "Protocol Dependency");
    count_vulns!(result.defi_primitive_vulnerabilities, "DeFi Primitive");
    count_vulns!(result.state_manipulation_vulnerabilities, "State Manipulation");
    count_vulns!(result.mev_attack_vulnerabilities, "MEV Attack");
    count_vulns!(result.governance_vulnerabilities, "Governance");
    count_vulns!(result.oracle_infrastructure_vulnerabilities, "Oracle Infrastructure");
    count_vulns!(result.lp_economic_vulnerabilities, "LP Economic");
    count_vulns!(result.black_swan_vulnerabilities, "Black Swan");
    count_vulns!(result.multi_vector_vulnerabilities, "Multi-Vector");
    count_vulns!(result.ai_detected_vulnerabilities, "AI Detected");
    count_vulns!(result.infrastructure_vulnerabilities, "Infrastructure");
    count_vulns!(result.atomic_composability_vulnerabilities, "Atomic Composability");
    count_vulns!(result.protocol_integration_vulnerabilities, "Protocol Integration");
    count_vulns!(result.advanced_mev_vulnerabilities, "Advanced MEV");
    count_vulns!(result.gas_economic_vulnerabilities, "Gas Economic");
    count_vulns!(result.flash_loan_vulnerabilities, "Flash Loan");
    count_vulns!(result.data_integrity_vulnerabilities, "Data Integrity");
    
    println!();
    
    // Find the biggest offenders
    let mut sorted: Vec<_> = type_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    
    println!("⚠️  TOP 5 NOISIEST ANALYZERS:\n");
    for (i, (name, count)) in sorted.iter().take(5).enumerate() {
        println!("{}. {}: {} findings", i + 1, name, count);
    }
    
    println!("\n💡 RECOMMENDATION:");
    println!("================");
    println!("The top analyzers listed above are likely producing false positives.");
    println!("These should be reviewed and their detection criteria tightened.");
    println!("\nPotential fixes:");
    println!("1. Disable the noisiest analyzers");
    println!("2. Add confidence thresholds");
    println!("3. Require multiple conditions to be met");
    println!("4. Whitelist known safe patterns");
    
    Ok(())
}
