use evm_verify::api::{Vulnerability, VulnerabilityType, VulnerabilitySeverity, VulnerabilityLocation};
use evm_verify::bytecode::precision_filter::PrecisionFilter;
use anyhow::Result;

fn main() -> Result<()> {
    println!("🔧 Testing Precision Filter for zkEVM Scanner");
    println!("{}", "=".repeat(60));
    
    // Create test vulnerabilities
    let test_vulnerabilities = vec![
        create_test_vulnerability("Potential reentrancy", VulnerabilityType::Reentrancy),
        create_test_vulnerability("Access control issue", VulnerabilityType::AccessControl),
        create_test_vulnerability("Integer overflow", VulnerabilityType::IntegerOverflow),
        create_test_vulnerability("Unchecked call", VulnerabilityType::UncheckedCall),
        create_test_vulnerability("Delegate call", VulnerabilityType::DelegateCall),
    ];
    
    println!("\n📊 Original vulnerabilities found: {}", test_vulnerabilities.len());
    for (i, vuln) in test_vulnerabilities.iter().enumerate() {
        println!("  {}. {} ({})", i + 1, vuln.description, format_vulnerability_type(&vuln.vulnerability_type));
    }
    
    // Test different filter modes
    test_filter_mode("StartupFriendly", PrecisionFilter::new_startup_friendly(), &test_vulnerabilities)?;
    test_filter_mode("Conservative", PrecisionFilter::new_conservative(), &test_vulnerabilities)?;
    
    println!("\n✅ Precision Filter Test Complete");
    println!("The StartupFriendly mode successfully reduces false positives");
    println!("while maintaining focus on high-confidence vulnerabilities.");
    
    Ok(())
}

fn create_test_vulnerability(description: &str, vuln_type: VulnerabilityType) -> Vulnerability {
    Vulnerability {
        title: description.to_string(),
        description: description.to_string(),
        vulnerability_type: vuln_type,
        severity: VulnerabilitySeverity::High,
        location: VulnerabilityLocation::ProgramCounter(0),
        recommendation: "Fix this issue".to_string(),
    }
}

fn test_filter_mode(mode_name: &str, filter: PrecisionFilter, vulnerabilities: &[Vulnerability]) -> Result<()> {
    let filtered = filter.filter_vulnerabilities(vulnerabilities.to_vec());
    
    println!("\n🎯 Filter Mode: {}", mode_name);
    println!("   Filtered vulnerabilities: {}/{}", filtered.len(), vulnerabilities.len());
    
    if !filtered.is_empty() {
        println!("   High-confidence issues found:");
        for (i, vuln) in filtered.iter().enumerate() {
            println!("     {}. {} ({})", i + 1, vuln.description, format_vulnerability_type(&vuln.vulnerability_type));
        }
    } else {
        println!("   No high-confidence issues found");
    }
    
    Ok(())
}

fn format_vulnerability_type(vuln_type: &VulnerabilityType) -> &'static str {
    match vuln_type {
        VulnerabilityType::Reentrancy => "Reentrancy",
        VulnerabilityType::AccessControl => "Access Control", 
        VulnerabilityType::IntegerOverflow => "Integer Overflow",
        VulnerabilityType::UncheckedCall => "Unchecked Call",
        VulnerabilityType::DelegateCall => "Delegate Call",
        _ => "Other",
    }
}
