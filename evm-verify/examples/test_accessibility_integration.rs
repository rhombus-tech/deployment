/// Test the integrated accessibility analysis in comprehensive analyzer

use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::args().nth(1)
        .unwrap_or_else(|| "0x0000000aa232009084bd71a5797d089aa4edfad4".to_string());
    
    println!("\n🧪 TESTING INTEGRATED ACCESSIBILITY ANALYSIS");
    println!("{}", "=".repeat(100));
    println!("Contract: {}", address);
    println!("{}", "=".repeat(100));
    
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let addr = Address::from_str(&address)?;
    
    let bytecode = provider.get_code(addr, None).await?;
    println!("\n📊 Bytecode size: {} bytes", bytecode.len());
    
    if bytecode.is_empty() {
        println!("❌ No bytecode found");
        return Ok(());
    }
    
    println!("\n⏳ Running comprehensive analysis with accessibility checks...");
    let analyzer = ComprehensiveSecurityAnalyzer::new(bytecode.to_vec());
    let result = analyzer.analyze();
    
    println!("\n{}", "=".repeat(100));
    println!("📊 ANALYSIS RESULTS");
    println!("{}", "=".repeat(100));
    
    println!("\n🔍 Reentrancy Vulnerabilities:");
    println!("   Total detected: {}", result.reentrancy_vulnerabilities.len());
    
    println!("\n🔒 Accessibility Analysis:");
    println!("   Total analyzed: {}", result.vulnerability_accessibility.len());
    println!("   🚨 Publicly exploitable: {}", result.publicly_exploitable_count);
    println!("   🔒 Access controlled: {}", result.access_controlled_count);
    
    if result.publicly_exploitable_count > 0 {
        println!("\n🚨 CRITICAL FINDING: {} vulnerabilities are PUBLICLY EXPLOITABLE!", 
                 result.publicly_exploitable_count);
        
        println!("\n📍 Exploitable Vulnerabilities:");
        for (i, access) in result.vulnerability_accessibility.iter()
            .filter(|a| a.is_publicly_accessible)
            .enumerate() 
        {
            println!("   {}. PC {}: Public access path found", i + 1, access.vulnerable_pc);
            if !access.access_path.is_empty() {
                println!("      Functions: {} in path", access.access_path.len());
            }
        }
    } else if result.access_controlled_count > 0 {
        println!("\n✅ SAFE: All {} vulnerabilities are access-controlled", 
                 result.access_controlled_count);
        
        println!("\n🛡️  Protected Vulnerabilities:");
        for (i, access) in result.vulnerability_accessibility.iter()
            .filter(|a| !a.is_publicly_accessible)
            .take(3)
            .enumerate() 
        {
            println!("   {}. PC {}: {} blocking controls", 
                     i + 1, access.vulnerable_pc, access.blocking_checks.len());
        }
        if result.access_controlled_count > 3 {
            println!("   ... and {} more", result.access_controlled_count - 3);
        }
    } else {
        println!("\n✅ No vulnerabilities with accessibility data");
    }
    
    println!("\n{}", "=".repeat(100));
    println!("🎯 RISK CLASSIFICATION");
    println!("{}", "=".repeat(100));
    
    let risk_level = if result.publicly_exploitable_count > 0 {
        "🔴 CRITICAL - Public Exploitation Possible"
    } else if result.access_controlled_count > 0 {
        "🟡 MEDIUM - Vulnerable Code (Access-Controlled)"
    } else {
        "🟢 LOW - No Accessible Vulnerabilities"
    };
    
    println!("\n{}", risk_level);
    
    if result.access_controlled_count > 0 && result.publicly_exploitable_count == 0 {
        println!("\n💡 Interpretation:");
        println!("   • Vulnerable code patterns exist");
        println!("   • Access controls prevent public exploitation");
        println!("   • Safe for regular users");
        println!("   • Recommendation: Owner should still fix underlying issues");
    }
    
    println!("\n{}", "=".repeat(100));
    println!("✅ TEST COMPLETE");
    println!("{}", "=".repeat(100));
    
    Ok(())
}
