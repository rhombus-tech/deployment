/// Validate Our Analyzers Against KNOWN Vulnerable Contracts
/// Tests detection accuracy by analyzing contracts that were actually exploited

use evm_verify::analysis::comprehensive_analyzer::ComprehensiveAnalyzerBuilder;
use evm_verify::analysis::vulnerability_validator::{VulnerabilityValidator, ExploitPatternMatcher};
use ethers::{providers::{Http, Provider, Middleware}, types::Address};
use std::str::FromStr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 VALIDATION TEST: Known Vulnerable Contracts");
    println!("="*70);
    println!("Testing our analyzers against contracts that were ACTUALLY exploited\n");
    
    let provider = Provider::<Http>::try_from("https://ethereum.publicnode.com")?;
    let provider = Arc::new(provider);
    
    // Known vulnerable contracts from major exploits
    let test_cases = vec![
        TestCase {
            name: "Euler Finance (Exploited $200M)",
            address: "0x27182842E098f60e3D576794A5bFFb0777E025d3", // Euler eToken
            expected_critical: vec!["isolated_market", "donation_attack"],
            expected_high: vec!["bad_debt_socialization"],
            description: "Isolated market manipulation + donation attack",
        },
        TestCase {
            name: "Cream Finance V1 (Exploited $130M)",
            address: "0x44fbebd2f576670a6c33f6fc0b00aa8c5753b322", // Cream cToken
            expected_critical: vec!["reentrancy"],
            expected_high: vec!["bad_debt"],
            description: "Reentrancy in borrow/repay flow",
        },
        TestCase {
            name: "bZx Protocol (Exploited Multiple Times)",
            address: "0x77f973FCaF871459aa58cd81881Ce453759281bC", // bZx
            expected_critical: vec!["oracle_manipulation", "flash_loan"],
            expected_high: vec!["liquidation_gaming"],
            description: "Oracle manipulation via flash loans",
        },
    ];
    
    let mut total_detected = 0;
    let mut total_expected = 0;
    
    for test_case in test_cases.iter() {
        println!("\n{'='*70}");
        println!("📋 {}", test_case.name);
        println!("📍 {}", test_case.address);
        println!("❗ {}", test_case.description);
        println!("{'='*70}");
        
        let address = match Address::from_str(test_case.address) {
            Ok(addr) => addr,
            Err(e) => {
                println!("❌ Invalid address: {}", e);
                continue;
            }
        };
        
        // Fetch bytecode
        let code: Vec<u8> = match provider.get_code(address, None).await {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                println!("❌ Failed to fetch bytecode: {}", e);
                continue;
            }
        };
        
        if code.is_empty() {
            println!("⚠️  No bytecode found");
            continue;
        }
        
        println!("✅ Bytecode fetched: {} bytes", code.len());
        
        // Run comprehensive analysis
        let analyzer = ComprehensiveAnalyzerBuilder::new(code.clone())
            .with_contract_address(test_case.address.to_string())
            .build();
        
        println!("🔬 Running comprehensive analysis...");
        let result = analyzer.analyze();
        
        // Validate with exploit pattern matcher
        let exploit_matcher = ExploitPatternMatcher::new(code.clone());
        
        println!("\n📊 DETECTION RESULTS:");
        println!("─────────────────────────────");
        
        // Check exploit patterns
        if exploit_matcher.matches_euler_pattern() {
            println!("✓ Detected: Euler exploit pattern (isolated market)");
            total_detected += 1;
        }
        if exploit_matcher.matches_cream_pattern() {
            println!("✓ Detected: Cream exploit pattern (reentrancy)");
            total_detected += 1;
        }
        if exploit_matcher.matches_mango_pattern() {
            println!("✓ Detected: Mango exploit pattern (oracle manipulation)");
            total_detected += 1;
        }
        
        // Check critical findings
        println!("\n🔴 Critical Vulnerabilities Found:");
        if !result.isolated_market_vulnerabilities.is_empty() {
            println!("  • Isolated Market Manipulation: {}", result.isolated_market_vulnerabilities.len());
            if test_case.expected_critical.contains(&"isolated_market") {
                println!("    ✓ EXPECTED (matches known exploit)");
                total_detected += 1;
            }
        }
        
        if !result.bad_debt_socialization_vulnerabilities.is_empty() {
            println!("  • Bad Debt Socialization: {}", result.bad_debt_socialization_vulnerabilities.len());
            if test_case.expected_high.contains(&"bad_debt") {
                println!("    ✓ EXPECTED (matches known exploit)");
                total_detected += 1;
            }
        }
        
        if !result.reentrancy_vulnerabilities.is_empty() {
            println!("  • Reentrancy: {}", result.reentrancy_vulnerabilities.len());
            if test_case.expected_critical.contains(&"reentrancy") {
                println!("    ✓ EXPECTED (matches known exploit)");
                total_detected += 1;
            }
        }
        
        // Apply validation
        let validator = VulnerabilityValidator::new(code.clone());
        
        // Validate bad debt findings
        let mut validated_bad_debt = 0;
        for vuln in &result.bad_debt_socialization_vulnerabilities {
            if validator.validate_bad_debt(vuln.location) {
                validated_bad_debt += 1;
            }
        }
        
        if validated_bad_debt > 0 {
            println!("\n✅ Validated Bad Debt Issues: {}/{}", 
                validated_bad_debt, 
                result.bad_debt_socialization_vulnerabilities.len()
            );
        }
        
        // Summary
        println!("\n📌 Analysis Metadata:");
        println!("  Total Vulnerabilities: {}", result.total_vulnerabilities);
        println!("  Critical: {}", result.security_summary.critical_count);
        println!("  High: {}", result.security_summary.high_count);
        println!("  Confidence: {:.1}%", result.analysis_confidence * 100.0);
        
        total_expected += test_case.expected_critical.len() + test_case.expected_high.len();
    }
    
    // Final validation report
    println!("\n\n");
    println!("="*70);
    println!("🏁 VALIDATION SUMMARY");
    println!("="*70);
    println!("Expected Vulnerabilities: {}", total_expected);
    println!("Detected: {}", total_detected);
    
    let detection_rate = if total_expected > 0 {
        (total_detected as f32 / total_expected as f32) * 100.0
    } else {
        0.0
    };
    
    println!("Detection Rate: {:.1}%", detection_rate);
    
    if detection_rate >= 70.0 {
        println!("\n✅ VALIDATION PASSED: Detecting real vulnerabilities");
    } else if detection_rate >= 50.0 {
        println!("\n⚠️  VALIDATION PARTIAL: Some real vulnerabilities detected");
    } else {
        println!("\n❌ VALIDATION FAILED: Missing too many real vulnerabilities");
    }
    
    println!("\n💡 Next Steps:");
    println!("   1. Review false negatives (missed vulnerabilities)");
    println!("   2. Tune confidence thresholds");
    println!("   3. Add more validation checks");
    println!("   4. Test against more exploited contracts");
    println!("="*70);
    
    Ok(())
}

struct TestCase {
    name: &'static str,
    address: &'static str,
    expected_critical: Vec<&'static str>,
    expected_high: Vec<&'static str>,
    description: &'static str,
}
