/// Check Seaport's 164 upgrade vulnerabilities in detail
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let addr = Address::from_str("0x0000000071727de22e5e9d8baf0edac6f37da032")?;
    let code = provider.get_code(addr, None).await?;
    
    println!("\n🔍 SEAPORT UPGRADE VULNERABILITY ANALYSIS");
    println!("{}", "=".repeat(100));
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let result = analyzer.analyze();
    
    println!("\n📊 UPGRADE VULNERABILITIES: {}", result.upgrade_vulnerabilities.len());
    println!("{}", "=".repeat(100));
    
    // Show details of upgrade vulnerabilities
    for (i, vuln) in result.upgrade_vulnerabilities.iter().enumerate().take(20) {
        println!("\n{}. Location: {}", i+1, vuln.location);
        println!("   Severity: {:?}", vuln.severity);
        println!("   Risk Type: {:?}", vuln.risk_type);
        println!("   Proxy Pattern: {:?}", vuln.proxy_pattern);
        println!("   Detection Confidence: {:.0}%", vuln.detection_confidence * 100.0);
        println!("   Description: {}", &vuln.description[..200.min(vuln.description.len())]);
    }
    
    if result.upgrade_vulnerabilities.len() > 20 {
        println!("\n... and {} more upgrade vulnerabilities", result.upgrade_vulnerabilities.len() - 20);
    }
    
    // Check if Seaport is actually upgradeable
    println!("\n{}", "=".repeat(100));
    println!("🔍 CRITICAL QUESTION: Is Seaport actually upgradeable?");
    println!("{}", "=".repeat(100));
    
    let has_delegatecall = result.upgrade_vulnerabilities.iter()
        .any(|v| v.description.contains("delegatecall") || v.description.contains("DELEGATECALL"));
    
    let has_proxy_pattern = result.upgrade_vulnerabilities.iter()
        .any(|v| v.description.contains("proxy") || v.description.contains("Proxy"));
        
    println!("\nDELEGATECALL detected: {}", has_delegatecall);
    println!("Proxy pattern detected: {}", has_proxy_pattern);
    
    if !has_delegatecall && !has_proxy_pattern {
        println!("\n⚠️  WARNING: 164 'upgrade' vulnerabilities but no DELEGATECALL/proxy?");
        println!("   This suggests FALSE POSITIVES - detector may be flagging non-upgrade patterns");
    }
    
    Ok(())
}
