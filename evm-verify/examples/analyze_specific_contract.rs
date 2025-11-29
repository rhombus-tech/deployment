/// Detailed analysis of a specific contract
/// Shows exactly what vulnerabilities are detected and why

use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use evm_verify::bytecode::SecuritySeverity;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get contract address from command line argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --example analyze_specific_contract <contract_address>");
        eprintln!("Example: cargo run --example analyze_specific_contract 0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae");
        std::process::exit(1);
    }
    
    let address = &args[1];
    
    println!("\n🔍 DETAILED VULNERABILITY ANALYSIS");
    println!("{}", "=".repeat(100));
    println!("Contract: {}", address);
    println!("{}", "=".repeat(100));
    
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let addr = Address::from_str(address)?;
    let code = provider.get_code(addr, None).await?;
    
    println!("\n📊 Contract Info:");
    println!("   Bytecode size: {} bytes", code.len());
    
    if code.is_empty() {
        println!("   ⚠️  No bytecode found (EOA or not deployed)");
        return Ok(());
    }
    
    println!("\n⏳ Running comprehensive analysis...\n");
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let result = analyzer.analyze();
    
    println!("{}", "=".repeat(100));
    println!("📊 ANALYSIS RESULTS");
    println!("{}", "=".repeat(100));
    
    println!("\n🎯 SUMMARY:");
    println!("   Total vulnerabilities: {}", result.total_vulnerabilities);
    println!("   Analysis confidence: {:.1}%", result.analysis_confidence * 100.0);
    
    // REENTRANCY ANALYSIS
    if !result.reentrancy_vulnerabilities.is_empty() {
        println!("\n{}", "-".repeat(100));
        println!("🔄 REENTRANCY VULNERABILITIES: {}", result.reentrancy_vulnerabilities.len());
        println!("{}", "-".repeat(100));
        
        for (i, vuln) in result.reentrancy_vulnerabilities.iter().enumerate() {
            println!("\n{}. Reentrancy at PC: {}", i+1, vuln.pc);
            println!("   Severity: {:?}", vuln.severity);
            println!("   Confidence: {:.0}%", vuln.confidence * 100.0);
            println!("   Description: {}", vuln.description);
            
            if matches!(vuln.severity, SecuritySeverity::Critical) {
                println!("   ⚠️  CRITICAL: This is a high-severity reentrancy vulnerability!");
            }
        }
    }
    
    // INTEGER OVERFLOW ANALYSIS
    if !result.integer_vulnerabilities.is_empty() {
        println!("\n{}", "-".repeat(100));
        println!("🔢 INTEGER VULNERABILITIES: {}", result.integer_vulnerabilities.len());
        println!("{}", "-".repeat(100));
        
        let high_conf: Vec<_> = result.integer_vulnerabilities.iter()
            .filter(|v| v.confidence >= 0.85)
            .collect();
        
        let density = if result.integer_vulnerabilities.len() > 0 {
            (high_conf.len() as f32 / result.integer_vulnerabilities.len() as f32) * 100.0
        } else {
            0.0
        };
        
        println!("\n   Total operations: {}", result.integer_vulnerabilities.len());
        println!("   High-confidence (≥85%): {}", high_conf.len());
        println!("   Vulnerability density: {:.1}%", density);
        
        if high_conf.len() >= 20 && density >= 10.0 {
            println!("   ⚠️  SYSTEMATIC PATTERN: Exceeds critical thresholds!");
        } else {
            println!("   ℹ️  Below systematic vulnerability threshold (need 20+ ops at 10%+ density)");
        }
        
        println!("\n   High-confidence operations:");
        for (i, vuln) in high_conf.iter().take(10).enumerate() {
            println!("   {}. PC: {}, Op: {:?}, Severity: {:?}, Conf: {:.0}%", 
                     i+1, vuln.pc, vuln.operation, vuln.severity, vuln.confidence * 100.0);
        }
        if high_conf.len() > 10 {
            println!("   ... and {} more", high_conf.len() - 10);
        }
    }
    
    // ECONOMIC VULNERABILITIES
    if !result.economic_vulnerabilities.is_empty() {
        println!("\n{}", "-".repeat(100));
        println!("💰 ECONOMIC VULNERABILITIES: {}", result.economic_vulnerabilities.len());
        println!("{}", "-".repeat(100));
        
        for (i, vuln) in result.economic_vulnerabilities.iter().enumerate() {
            println!("\n{}. Attack Type: {:?}", i+1, vuln.attack_type);
            println!("   Severity: {:?}", vuln.severity);
            println!("   Confidence: {:.0}%", vuln.detection_confidence * 100.0);
            println!("   Description: {}", vuln.description);
            
            if vuln.detection_confidence >= 0.95 && matches!(vuln.severity, SecuritySeverity::Critical) {
                println!("   ⚠️  HIGH CONFIDENCE CRITICAL: Real economic exploit risk!");
            } else {
                println!("   ℹ️  Below critical threshold (need 95%+ confidence + Critical severity)");
            }
        }
    }
    
    // FINAL VERDICT
    println!("\n{}", "=".repeat(100));
    println!("🎯 FINAL VERDICT");
    println!("{}", "=".repeat(100));
    
    let has_critical_reentrancy = result.reentrancy_vulnerabilities.iter()
        .any(|v| matches!(v.severity, SecuritySeverity::Critical));
    
    let high_conf_integers: Vec<_> = result.integer_vulnerabilities.iter()
        .filter(|v| (matches!(v.severity, SecuritySeverity::Critical) && v.confidence > 0.80) || 
                    (matches!(v.severity, SecuritySeverity::High) && v.confidence >= 0.85) ||
                    v.confidence >= 0.95)
        .collect();
    
    let density = if result.integer_vulnerabilities.len() > 0 {
        (high_conf_integers.len() as f32 / result.integer_vulnerabilities.len() as f32) * 100.0
    } else {
        0.0
    };
    
    let has_critical_integer = high_conf_integers.len() >= 20 && density >= 10.0;
    
    let has_high_conf_economic = result.economic_vulnerabilities.iter()
        .any(|v| v.detection_confidence >= 0.95 && 
                 matches!(v.severity, SecuritySeverity::Critical));
    
    println!("\n📋 Vulnerability Checks:");
    println!("   [{}] Critical Reentrancy: {}", 
             if has_critical_reentrancy { "X" } else { " " },
             if has_critical_reentrancy { "DETECTED" } else { "Not found" });
    
    println!("   [{}] Systematic Integer Overflow: {}", 
             if has_critical_integer { "X" } else { " " },
             if has_critical_integer { 
                 format!("DETECTED ({} ops at {:.1}% density)", high_conf_integers.len(), density)
             } else { 
                 format!("Not systematic ({} ops at {:.1}% density)", high_conf_integers.len(), density)
             });
    
    println!("   [{}] High-Confidence Economic: {}", 
             if has_high_conf_economic { "X" } else { " " },
             if has_high_conf_economic { "DETECTED" } else { "Not found" });
    
    if has_critical_reentrancy || has_critical_integer || has_high_conf_economic {
        println!("\n⚠️  VERDICT: CRITICAL VULNERABILITY");
        println!("\nReasons:");
        if has_critical_reentrancy {
            println!("   - Critical severity reentrancy detected");
        }
        if has_critical_integer {
            println!("   - Systematic integer overflow pattern ({}+ ops at {}%+ density)", 
                     high_conf_integers.len(), density);
        }
        if has_high_conf_economic {
            println!("   - High-confidence critical economic vulnerability");
        }
    } else {
        println!("\n✅ VERDICT: NOT CRITICALLY VULNERABLE");
        println!("\n   While the contract has some findings, none meet the critical thresholds:");
        println!("   - Reentrancy: None at Critical severity");
        println!("   - Integer: {:.1}% density (need 10%+) or {} ops (need 20+)", density, high_conf_integers.len());
        println!("   - Economic: None at 95%+ confidence + Critical severity");
    }
    
    println!("\n{}", "=".repeat(100));
    
    Ok(())
}
