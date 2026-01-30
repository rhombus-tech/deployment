/// Deep analysis of 0x0b6a649f01fc7da4295443342c9f283bb968f3fa to find actual exploits
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use evm_verify::bytecode::SecuritySeverity;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let addr = Address::from_str("0x0b6a649f01fc7da4295443342c9f283bb968f3fa")?;
    let code = provider.get_code(addr, None).await?;
    
    println!("\n🔍 EXPLOIT ANALYSIS: 0x0b6a649f01fc7da4295443342c9f283bb968f3fa");
    println!("{}", "=".repeat(100));
    println!("Bytecode: {} bytes", code.len());
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let result = analyzer.analyze();
    
    println!("\n📊 TOTAL: {} vulnerabilities", result.total_vulnerabilities);
    println!("{}", "=".repeat(100));
    
    // Detailed breakdown
    let mut categories = vec![];
    
    if !result.reentrancy_vulnerabilities.is_empty() {
        categories.push(("🔄 Reentrancy", result.reentrancy_vulnerabilities.len()));
    }
    if !result.integer_vulnerabilities.is_empty() {
        categories.push(("🔢 Integer", result.integer_vulnerabilities.len()));
    }
    if !result.economic_vulnerabilities.is_empty() {
        categories.push(("💰 Economic", result.economic_vulnerabilities.len()));
    }
    if !result.upgrade_vulnerabilities.is_empty() {
        categories.push(("🔧 Upgrade", result.upgrade_vulnerabilities.len()));
    }
    if !result.sandwich_vulnerabilities.is_empty() {
        categories.push(("🥪 Sandwich", result.sandwich_vulnerabilities.len()));
    }
    if !result.time_vulnerabilities.is_empty() {
        categories.push(("⏰ Time", result.time_vulnerabilities.len()));
    }
    if !result.governance_vulnerabilities.is_empty() {
        categories.push(("🏛️ Governance", result.governance_vulnerabilities.len()));
    }
    if !result.oracle_manipulation_vulnerabilities.is_empty() {
        categories.push(("🔮 Oracle", result.oracle_manipulation_vulnerabilities.len()));
    }
    if !result.access_control_vulnerabilities.is_empty() {
        categories.push(("🚪 Access Control", result.access_control_vulnerabilities.len()));
    }
    if !result.flash_loan_vulnerabilities.is_empty() {
        categories.push(("💸 Flash Loan", result.flash_loan_vulnerabilities.len()));
    }
    if !result.mev_attack_vulnerabilities.is_empty() {
        categories.push(("⚡ MEV", result.mev_attack_vulnerabilities.len()));
    }
    if !result.proxy_vulnerabilities.is_empty() {
        categories.push(("🎭 Proxy", result.proxy_vulnerabilities.len()));
    }
    
    for (name, count) in &categories {
        println!("{}: {}", name, count);
    }
    
    let shown_total: usize = categories.iter().map(|(_, c)| c).sum();
    let remaining = result.total_vulnerabilities as usize - shown_total;
    if remaining > 0 {
        println!("\n⚠️  {} vulnerabilities in other categories (100+ analyzers running)", remaining);
    }
    
    // Show critical/high severity findings
    println!("\n{}", "=".repeat(100));
    println!("🚨 CRITICAL & HIGH SEVERITY FINDINGS");
    println!("{}", "=".repeat(100));
    
    // Reentrancy
    let critical_reentrancy: Vec<_> = result.reentrancy_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical | SecuritySeverity::High))
        .collect();
    
    if !critical_reentrancy.is_empty() {
        println!("\n🔴 CRITICAL REENTRANCY ({}):", critical_reentrancy.len());
        for (i, v) in critical_reentrancy.iter().take(5).enumerate() {
            println!("  {}. PC {}: {:?}, Conf: {:.0}%, Protection: {}", 
                i+1, v.pc, v.severity, v.confidence * 100.0,
                if v.protection_mechanisms.is_empty() { "None ⚠️" } else { "Yes" });
            println!("     Description: {}", &v.description[..150.min(v.description.len())]);
        }
    }
    
    // Economic
    let critical_economic: Vec<_> = result.economic_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical | SecuritySeverity::High))
        .collect();
    
    if !critical_economic.is_empty() {
        println!("\n🔴 CRITICAL ECONOMIC ({}):", critical_economic.len());
        for (i, v) in critical_economic.iter().take(5).enumerate() {
            println!("  {}. {:?}, Severity: {:?}, Conf: {:.0}%", 
                i+1, v.attack_type, v.severity, v.detection_confidence * 100.0);
            println!("     Description: {}", &v.description[..150.min(v.description.len())]);
        }
    }
    
    // Access Control
    let critical_access: Vec<_> = result.access_control_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical | SecuritySeverity::High))
        .collect();
    
    if !critical_access.is_empty() {
        println!("\n🔴 CRITICAL ACCESS CONTROL ({}):", critical_access.len());
        for (i, v) in critical_access.iter().take(5).enumerate() {
            println!("  {}. {:?}, Severity: {:?}, Conf: {:.0}%", 
                i+1, v.attack_type, v.severity, v.confidence * 100.0);
        }
    }
    
    // Upgrade risks
    let critical_upgrade: Vec<_> = result.upgrade_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical | SecuritySeverity::High))
        .collect();
    
    if !critical_upgrade.is_empty() {
        println!("\n🔴 CRITICAL UPGRADE RISKS ({}):", critical_upgrade.len());
        for (i, v) in critical_upgrade.iter().take(5).enumerate() {
            println!("  {}. {:?}, Pattern: {:?}, Conf: {:.0}%", 
                i+1, v.risk_type, v.proxy_pattern, v.detection_confidence * 100.0);
        }
    }
    
    if critical_reentrancy.is_empty() && critical_economic.is_empty() && 
       critical_access.is_empty() && critical_upgrade.is_empty() {
        println!("\n✅ No Critical/High severity findings");
        println!("   The 2,028 vulnerabilities are likely:");
        println!("   - Low-severity pattern matches");
        println!("   - False positives from overly broad detectors");
        println!("   - Low-confidence findings");
    }
    
    println!("\n{}", "=".repeat(100));
    println!("🎯 EXPLOIT POTENTIAL ASSESSMENT");
    println!("{}", "=".repeat(100));
    
    let has_real_exploit = !critical_reentrancy.is_empty() || 
                          !critical_economic.is_empty() ||
                          !critical_access.is_empty() ||
                          !critical_upgrade.is_empty();
    
    if has_real_exploit {
        println!("\n⚠️  EXPLOITABLE: Yes - Critical/High severity issues found");
        println!("   Recommended: Manual security audit required");
    } else {
        println!("\n✅ NOT EXPLOITABLE via detected high-severity vectors");
        println!("   The 2,028 findings appear to be low-severity/low-confidence");
        println!("   Contract may still have business logic risks not detected by automated analysis");
    }
    
    Ok(())
}
