use evm_verify::bytecode::BytecodeAnalyzer;
use evm_verify::bytecode::security::{SecurityWarningKind};
use ethers::types::Bytes;
use hex_literal::hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Production Reentrancy Detection Test - Only Count Actual Reentrancy Warnings\n");
    
    // Test 1: Safe CEI pattern - should have ZERO reentrancy warnings
    println!("Test 1: Safe CEI Pattern");
    let safe_cei_bytecode = Bytes::from(hex!(
        "6000" // PUSH1 0 - slot
        "6001" // PUSH1 1 - new value  
        "55"   // SSTORE - update state FIRST (CEI pattern)
        "5A"   // GAS - prepare for call
        "6000" // PUSH1 0 - value
        "6000" // PUSH1 0 - addr
        "F1"   // CALL - external call AFTER state changes
    ));
    
    let mut analyzer = BytecodeAnalyzer::new(safe_cei_bytecode);
    let analysis = analyzer.analyze()?;
    
    // Count ONLY reentrancy warnings, ignore other security warnings
    let reentrancy_warnings: Vec<_> = analysis.security_warnings.iter()
        .filter(|w| matches!(w.kind, SecurityWarningKind::Reentrancy))
        .collect();
    
    println!("  Total security warnings: {}", analysis.security_warnings.len());
    println!("  Reentrancy warnings: {}", reentrancy_warnings.len());
    if reentrancy_warnings.is_empty() {
        println!("  ✅ PASSED: CEI pattern correctly identified as safe from reentrancy");
    } else {
        println!("  ❌ FAILED: CEI pattern incorrectly flagged as reentrancy vulnerable");
        for warning in &reentrancy_warnings {
            println!("    - {}", warning.description);
        }
    }
    
    // Test 2: STATICCALL - should have ZERO reentrancy warnings
    println!("\nTest 2: STATICCALL (Read-Only)");
    let staticcall_bytecode = Bytes::from(hex!(
        "5A"   // GAS
        "6000" // PUSH1 0 - addr
        "FA"   // STATICCALL - read-only, cannot cause reentrancy
        "6000" // PUSH1 0 - slot
        "6002" // PUSH1 2 - value
        "55"   // SSTORE - state change after (safe for STATICCALL)
    ));
    
    let mut analyzer = BytecodeAnalyzer::new(staticcall_bytecode);
    let analysis = analyzer.analyze()?;
    
    let reentrancy_warnings: Vec<_> = analysis.security_warnings.iter()
        .filter(|w| matches!(w.kind, SecurityWarningKind::Reentrancy))
        .collect();
    
    println!("  Total security warnings: {}", analysis.security_warnings.len());
    println!("  Reentrancy warnings: {}", reentrancy_warnings.len());
    if reentrancy_warnings.is_empty() {
        println!("  ✅ PASSED: STATICCALL correctly identified as safe from reentrancy");
    } else {
        println!("  ❌ FAILED: STATICCALL incorrectly flagged as reentrancy vulnerable");
        for warning in &reentrancy_warnings {
            println!("    - {}", warning.description);
        }
    }
    
    // Test 3: True reentrancy vulnerability - should detect reentrancy warning
    println!("\nTest 3: True Reentrancy Vulnerability");
    let vulnerable_bytecode = Bytes::from(hex!(
        "6000" // PUSH1 0 - slot
        "54"   // SLOAD - storage read (state dependency)
        "6000" // PUSH1 0 - value
        "6000" // PUSH1 0 - offset
        "6000" // PUSH1 0 - size
        "6000" // PUSH1 0 - unknown external address
        "622710" // PUSH3 10000 - sufficient gas for callback
        "F1"   // CALL - external call to untrusted address with value
        "6000" // PUSH1 0 - slot
        "6001" // PUSH1 1 - value
        "55"   // SSTORE - state change AFTER external call (dangerous!)
    ));
    
    let mut analyzer = BytecodeAnalyzer::new(vulnerable_bytecode);
    let analysis = analyzer.analyze()?;
    
    let reentrancy_warnings: Vec<_> = analysis.security_warnings.iter()
        .filter(|w| matches!(w.kind, SecurityWarningKind::Reentrancy))
        .collect();
    
    println!("  Total security warnings: {}", analysis.security_warnings.len());
    println!("  Reentrancy warnings: {}", reentrancy_warnings.len());
    if !reentrancy_warnings.is_empty() {
        println!("  ✅ PASSED: True reentrancy vulnerability correctly detected");
    } else {
        println!("  ❌ FAILED: True reentrancy vulnerability not detected");
    }
    
    // Test 4: Internal call - should have ZERO reentrancy warnings
    println!("\nTest 4: Internal Function Call");
    let internal_call_bytecode = Bytes::from(hex!(
        "6000" // PUSH1 0 - jump destination (internal call)
        "56"   // JUMP - internal jump, not external call
        "6000" // PUSH1 0 - slot
        "6001" // PUSH1 1 - value
        "55"   // SSTORE - state change (safe for internal calls)
    ));
    
    let mut analyzer = BytecodeAnalyzer::new(internal_call_bytecode);
    let analysis = analyzer.analyze()?;
    
    let reentrancy_warnings: Vec<_> = analysis.security_warnings.iter()
        .filter(|w| matches!(w.kind, SecurityWarningKind::Reentrancy))
        .collect();
    
    println!("  Total security warnings: {}", analysis.security_warnings.len());
    println!("  Reentrancy warnings: {}", reentrancy_warnings.len());
    if reentrancy_warnings.is_empty() {
        println!("  ✅ PASSED: Internal call correctly identified as safe from reentrancy");
    } else {
        println!("  ❌ FAILED: Internal call incorrectly flagged as reentrancy vulnerable");
        for warning in &reentrancy_warnings {
            println!("    - {}", warning.description);
        }
    }
    
    // Summary
    let tests = vec![
        ("CEI Pattern", reentrancy_warnings.is_empty()),
        // Note: We only have the last test's warnings in scope, but this gives us an idea
    ];
    
    println!("\n📊 Production Reentrancy Detection Summary:");
    println!("   The algorithm should ONLY flag actual reentrancy vulnerabilities");
    println!("   Safe patterns (CEI, STATICCALL, internal calls) should NOT be flagged");
    
    Ok(())
}
