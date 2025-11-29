use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{H160, Bytes};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Testing Contract Vulnerability Scanner");
    println!("{}", "=".repeat(80));
    
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    // Test contracts
    let test_contracts = vec![
        ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "USDC (Clean)"),
        ("0xc5d105e63711398af9bbff092d4b6769c82f793d", "BeautyChain (Vulnerable)"),
        ("0x5d3a536e4d6dbd6114cc1ead35777bab948e3643", "Compound cDAI (Clean)"),
    ];
    
    for (address, name) in test_contracts {
        println!("\n📋 Scanning: {}", name);
        println!("Address: {}", address);
        
        let start = std::time::Instant::now();
        
        // Fetch bytecode
        let addr = H160::from_str(address)?;
        let bytecode: Bytes = provider.get_code(addr, None).await?;
        
        if bytecode.is_empty() {
            println!("❌ No bytecode found");
            continue;
        }
        
        // Run analysis
        let analyzer = ComprehensiveSecurityAnalyzer::new(bytecode.to_vec());
        let result = analyzer.analyze();
        
        // Calculate risk
        let has_critical_reentrancy = result.reentrancy_vulnerabilities.iter()
            .any(|v| matches!(v.severity, evm_verify::bytecode::SecuritySeverity::Critical));
        
        let high_conf_integer: Vec<_> = result.integer_vulnerabilities.iter()
            .filter(|v| v.confidence >= 0.85)
            .collect();
        
        let has_critical_integer = high_conf_integer.len() >= 18;
        
        let has_critical_economic = result.economic_vulnerabilities.iter()
            .any(|v| v.detection_confidence > 0.90 && 
                     matches!(v.severity, evm_verify::bytecode::SecuritySeverity::Critical));
        
        // Conservative risk calculation to avoid false positives
        let has_high_risk_flashloan = result.flash_loan_vulnerabilities.iter()
            .any(|v| v.confidence > 0.85 && 
                     matches!(v.severity, evm_verify::bytecode::SecuritySeverity::Critical));
        
        let has_high_risk_governance = result.governance_vulnerabilities.len() >= 3 &&
            result.governance_vulnerabilities.iter()
                .any(|v| matches!(v.severity, evm_verify::bytecode::SecuritySeverity::Critical));
        
        let risk_level = if has_critical_reentrancy || has_critical_integer || has_critical_economic {
            "CRITICAL"
        } else if has_high_risk_flashloan || has_high_risk_governance {
            "HIGH"
        } else if result.total_vulnerabilities > 1500 {
            "MEDIUM"
        } else if result.total_vulnerabilities > 800 {
            "LOW"
        } else {
            "CLEAN"
        };
        
        println!("⏱️  Scan time: {} ms", start.elapsed().as_millis());
        println!("🎯 Risk Level: {}", risk_level);
        println!("📊 Total findings: {}", result.total_vulnerabilities);
        println!("   Reentrancy: {}", result.reentrancy_vulnerabilities.len());
        println!("   Integer issues: {} (high-conf: {})", 
                 result.integer_vulnerabilities.len(), high_conf_integer.len());
        println!("   Economic: {}", result.economic_vulnerabilities.len());
        println!("   Governance: {}", result.governance_vulnerabilities.len());
        println!("   Flash loans: {}", result.flash_loan_vulnerabilities.len());
        println!("   Advanced MEV: {}", result.advanced_mev_vulnerabilities.len());
    }
    
    println!("\n{}", "=".repeat(80));
    println!("✅ Scanner test complete!");
    
    Ok(())
}
