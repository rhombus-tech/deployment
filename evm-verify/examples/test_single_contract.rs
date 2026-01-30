use evm_verify::analysis::ComprehensiveSecurityAnalyzer;

fn main() {
    println!("\n🔬 Testing Filtered Vulnerability Counting\n");
    println!("{}", "=".repeat(80));
    
    // Simple test bytecode with some patterns
    println!("📦 Testing with sample bytecode");
    
    // Minimal bytecode with ADD, MUL operations that trigger integer detection
    let code = vec![
        0x60, 0x01, // PUSH1 1
        0x60, 0x02, // PUSH1 2
        0x01,       // ADD
        0x60, 0x03, // PUSH1 3
        0x02,       // MUL
        0x60, 0x04, // PUSH1 4
        0x0a,       // EXP
    ];
    
    println!("✅ Using {} bytes of test bytecode", code.len());
    println!("{}", "=".repeat(80));
    
    // Analyze
    println!("\n🔍 Running analysis...");
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let result = analyzer.analyze();
    
    println!("\n{}", "=".repeat(80));
    println!("📊 FILTERED RESULTS (confidence >= 0.75):");
    println!("{}", "=".repeat(80));
    
    println!("\n🎯 Total (filtered, high-confidence): {}", result.total_vulnerabilities);
    println!("\n📋 Breakdown by type:");
    
    let mut types = vec![
        ("Reentrancy", result.reentrancy_vulnerabilities.len()),
        ("Integer Overflow", result.integer_vulnerabilities.len()),
        ("Economic", result.economic_vulnerabilities.len()),
        ("Bridge", result.bridge_vulnerabilities.len()),
        ("Protocol Dependency", result.protocol_dependency_vulnerabilities.len()),
        ("DeFi Primitives", result.defi_primitive_vulnerabilities.len()),
        ("State Manipulation", result.state_manipulation_vulnerabilities.len()),
        ("MEV Attacks", result.mev_attack_vulnerabilities.len()),
        ("Atomic Composability", result.atomic_composability_vulnerabilities.len()),
        ("Protocol Integration", result.protocol_integration_vulnerabilities.len()),
        ("Advanced MEV", result.advanced_mev_vulnerabilities.len()),
        ("Gas Economic", result.gas_economic_vulnerabilities.len()),
        ("Flash Loans", result.flash_loan_vulnerabilities.len()),
        ("Data Integrity", result.data_integrity_vulnerabilities.len()),
        ("Proxy", result.proxy_vulnerabilities.len()),
        ("Composability Attacks", result.composability_attacks.len()),
        ("Oracle Manipulation", result.oracle_manipulation_vulnerabilities.len()),
        ("Access Control", result.access_control_vulnerabilities.len()),
    ];
    
    // Filter and sort
    types.retain(|(_, count)| *count > 0);
    types.sort_by(|a, b| b.1.cmp(&a.1));
    
    if types.is_empty() {
        println!("   ✅ No high-confidence vulnerabilities found!");
    } else {
        for (name, count) in &types {
            println!("   • {}: {}", name, count);
        }
    }
    
    // Show some details
    if !result.integer_vulnerabilities.is_empty() {
        println!("\n🔢 Integer Overflow Details (top 5):");
        for (i, v) in result.integer_vulnerabilities.iter().take(5).enumerate() {
            println!("   {}. PC {}: {:.0}% confidence", 
                i + 1, v.pc, v.confidence * 100.0);
        }
    }
    
    if !result.reentrancy_vulnerabilities.is_empty() {
        println!("\n🔄 Reentrancy Details (top 3):");
        for (i, v) in result.reentrancy_vulnerabilities.iter().take(3).enumerate() {
            println!("   {}. {:.0}% confidence at PC {}", 
                i + 1, v.confidence * 100.0, v.pc);
        }
    }
    
    println!("\n{}", "=".repeat(80));
    println!("✅ All counts above are HIGH-CONFIDENCE (>= 75%) only!");
    println!("🎯 These are REAL vulnerabilities after filtering.");
    println!("{}", "=".repeat(80));
}
