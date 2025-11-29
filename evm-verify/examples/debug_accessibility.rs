/// Debug the accessibility analyzer to understand what's happening

use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;
use evm_verify::analysis::advanced_reentrancy_detector::AdvancedReentrancyDetector;
use evm_verify::analysis::vulnerability_accessibility_analyzer::VulnerabilityAccessibilityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::args().nth(1)
        .unwrap_or_else(|| "0x0000000aa232009084bd71a5797d089aa4edfad4".to_string());
    
    println!("\n🐛 DEBUG: Accessibility Analyzer");
    println!("{}", "=".repeat(80));
    println!("Contract: {}\n", address);
    
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let addr = Address::from_str(&address)?;
    let bytecode = provider.get_code(addr, None).await?;
    
    println!("Bytecode size: {} bytes\n", bytecode.len());
    
    // Detect vulnerabilities
    let detector = AdvancedReentrancyDetector::new(bytecode.to_vec());
    let vulns = detector.detect_vulnerabilities();
    
    println!("Found {} reentrancy vulnerabilities:", vulns.len());
    for v in &vulns {
        println!("  - PC {}: {:?}, Conf: {:.0}%", v.pc, v.severity, v.confidence * 100.0);
    }
    
    // Analyze accessibility
    let vulnerable_pcs: Vec<usize> = vulns.iter().map(|v| v.pc).collect();
    let mut analyzer = VulnerabilityAccessibilityAnalyzer::new(bytecode.to_vec());
    let results = analyzer.analyze(&vulnerable_pcs);
    
    println!("\n{}", "=".repeat(80));
    println!("DETAILED ACCESSIBILITY ANALYSIS:\n");
    
    for (i, result) in results.iter().enumerate() {
        println!("{}. Vulnerability at PC {}", i + 1, result.vulnerable_pc);
        println!("   Publicly accessible: {}", result.is_publicly_accessible);
        println!("   Confidence: {:.0}%", result.confidence * 100.0);
        println!("   Blocking checks found: {}", result.blocking_checks.len());
        
        if !result.blocking_checks.is_empty() {
            println!("   First 5 blocking checks:");
            for (j, check) in result.blocking_checks.iter().take(5).enumerate() {
                println!("     {}. {:?}", j + 1, check);
            }
            if result.blocking_checks.len() > 5 {
                println!("     ... and {} more", result.blocking_checks.len() - 5);
            }
        }
        
        if !result.access_path.is_empty() {
            println!("   Access path:");
            for node in &result.access_path {
                println!("     - PC {}: {:?}", node.pc, node.node_type);
            }
        }
        
        println!();
    }
    
    println!("{}", "=".repeat(80));
    println!("CRITICAL QUESTION:");
    println!("Are these {} checks ACTUALLY blocking access?", 
             results.iter().map(|r| r.blocking_checks.len()).sum::<usize>());
    println!("Or are they just ANY require/check in the bytecode?");
    println!("{}", "=".repeat(80));
    
    Ok(())
}
