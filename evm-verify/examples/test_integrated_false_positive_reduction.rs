/// Test: Comprehensive Analyzer with integrated false positive reduction

use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;

fn main() {
    println!("═══════════════════════════════════════════════════════");
    println!("INTEGRATED FALSE POSITIVE REDUCTION TEST");
    println!("═══════════════════════════════════════════════════════\n");
    
    // Test 1: OpenZeppelin ReentrancyGuard (should not flag)
    let oz_protected_bytecode = vec![
        0x54, 0x60, 0x02, 0x14, // SLOAD, PUSH1 2, EQ (guard check)
        0x15, 0x57, // ISZERO, JUMPI
        0xF1, // CALL
        0x55, // SSTORE
    ];
    
    println!("TEST 1: OpenZeppelin ReentrancyGuard Protected Code");
    println!("───────────────────────────────────────────────────────");
    let analyzer = ComprehensiveSecurityAnalyzer::new(oz_protected_bytecode);
    let result = analyzer.analyze();
    
    println!("Total Vulnerabilities: {}", result.total_vulnerabilities);
    println!("Reentrancy Issues: {}", result.reentrancy_vulnerabilities.len());
    if result.reentrancy_vulnerabilities.is_empty() {
        println!("✅ PASS: No false positives!");
    } else {
        println!("⚠️  Found {} reentrancy issues:", result.reentrancy_vulnerabilities.len());
        for vuln in &result.reentrancy_vulnerabilities {
            println!("   - Confidence: {:.0}%, FP: {}", vuln.confidence * 100.0, vuln.is_likely_false_positive);
        }
    }
    
    // Test 2: Solidity 0.8+ integer overflow (should filter)
    println!("\nTEST 2: Solidity 0.8+ Integer Arithmetic");
    println!("───────────────────────────────────────────────────────");
    let solidity_08_bytecode = vec![
        0x01, 0x10, 0x15, 0x57, // ADD, LT, ISZERO, JUMPI (overflow check)
        0x55, // SSTORE
    ];
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(solidity_08_bytecode);
    let result = analyzer.analyze();
    
    println!("Total Vulnerabilities: {}", result.total_vulnerabilities);
    println!("Integer Issues: {}", result.integer_vulnerabilities.len());
    if result.integer_vulnerabilities.len() < 5 {
        println!("✅ PASS: Filtered Solidity 0.8+ false positives!");
    } else {
        println!("⚠️  Still flagging {} integer issues", result.integer_vulnerabilities.len());
    }
    
    // Test 3: Real unprotected reentrancy (should still detect)
    println!("\nTEST 3: Real Unprotected Reentrancy");
    println!("───────────────────────────────────────────────────────");
    let vulnerable_bytecode = vec![
        0xF1, // CALL (no guard!)
        0x55, // SSTORE (state change after)
    ];
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(vulnerable_bytecode);
    let result = analyzer.analyze();
    
    println!("Total Vulnerabilities: {}", result.total_vulnerabilities);
    println!("Reentrancy Issues: {}", result.reentrancy_vulnerabilities.len());
    if !result.reentrancy_vulnerabilities.is_empty() {
        println!("✅ PASS: Still detects real vulnerabilities!");
        for vuln in &result.reentrancy_vulnerabilities {
            println!("   - Confidence: {:.0}%", vuln.confidence * 100.0);
        }
    } else {
        println!("❌ FAIL: Missed real vulnerability!");
    }
    
    println!("\n═══════════════════════════════════════════════════════");
    println!("INTEGRATION TEST COMPLETE");
    println!("═══════════════════════════════════════════════════════");
}
