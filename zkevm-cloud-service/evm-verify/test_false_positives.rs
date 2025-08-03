use evm_verify::bytecode::BytecodeAnalyzer;
use ethers::types::Bytes;
use hex_literal::hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Testing Advanced Reentrancy Detection for False Positives\n");
    
    // Test 1: Safe pattern - checks-effects-interactions (state changes before external call)
    println!("Test 1: Safe CEI Pattern");
    let safe_cei_bytecode = Bytes::from(hex!(
        "6000" // PUSH1 0 - slot
        "6001" // PUSH1 1 - new value  
        "55"   // SSTORE - update state FIRST
        "5A"   // GAS - prepare for call
        "6000" // PUSH1 0 - value
        "6000" // PUSH1 0 - addr
        "F1"   // CALL - external call AFTER state changes
    ));
    
    let mut analyzer = BytecodeAnalyzer::new(safe_cei_bytecode);
    analyzer.set_test_mode(false); // Enable full analysis
    let analysis = analyzer.analyze()?;
    
    println!("  Warnings detected: {}", analysis.security_warnings.len());
    if analysis.security_warnings.is_empty() {
        println!("  ✅ PASSED: CEI pattern correctly identified as safe");
    } else {
        println!("  ❌ FAILED: CEI pattern flagged as vulnerable (false positive)");
        for warning in &analysis.security_warnings {
            println!("    Warning: {}", warning.description);
        }
    }
    
    // Test 2: Read-only pattern (no state writes after external call)
    println!("\nTest 2: Read-Only External Call");
    let readonly_bytecode = Bytes::from(hex!(
        "6000" // PUSH1 0
        "54"   // SLOAD - read storage
        "5A"   // GAS
        "6000" // PUSH1 0 - value
        "6000" // PUSH1 0 - addr
        "FA"   // STATICCALL - read-only call, no reentrancy risk
        "50"   // POP result
    ));
    
    let mut analyzer2 = BytecodeAnalyzer::new(readonly_bytecode);
    analyzer2.set_test_mode(false);
    let analysis2 = analyzer2.analyze()?;
    
    println!("  Warnings detected: {}", analysis2.security_warnings.len());
    if analysis2.security_warnings.is_empty() {
        println!("  ✅ PASSED: STATICCALL correctly identified as safe");
    } else {
        println!("  ❌ FAILED: STATICCALL flagged as vulnerable (false positive)");
    }
    
    // Test 3: True vulnerability - classic reentrancy
    println!("\nTest 3: True Reentrancy Vulnerability");
    let vulnerable_bytecode = Bytes::from(hex!(
        "6000" // PUSH1 0
        "54"   // SLOAD - read balance
        "5A"   // GAS
        "6000" // PUSH1 0 - value
        "6000" // PUSH1 0 - addr  
        "F1"   // CALL - external call
        "6000" // PUSH1 0 - slot
        "6001" // PUSH1 1 - value
        "55"   // SSTORE - update state AFTER external call (vulnerable!)
    ));
    
    let mut analyzer3 = BytecodeAnalyzer::new(vulnerable_bytecode);
    analyzer3.set_test_mode(false);
    let analysis3 = analyzer3.analyze()?;
    
    println!("  Warnings detected: {}", analysis3.security_warnings.len());
    if !analysis3.security_warnings.is_empty() {
        println!("  ✅ PASSED: True vulnerability correctly detected");
        for warning in &analysis3.security_warnings {
            println!("    Warning: {}", warning.description);
        }
    } else {
        println!("  ❌ FAILED: True vulnerability missed (false negative)");
    }
    
    // Test 4: Internal function call (not external reentrancy risk)
    println!("\nTest 4: Internal Function Call");
    let internal_call_bytecode = Bytes::from(hex!(
        "6000" // PUSH1 0
        "54"   // SLOAD - read storage
        "6020" // PUSH1 32 - jump destination (internal function)
        "56"   // JUMP - internal call
        "5B"   // JUMPDEST - function start
        "6000" // PUSH1 0
        "55"   // SSTORE - state change in internal function
    ));
    
    let mut analyzer4 = BytecodeAnalyzer::new(internal_call_bytecode);
    analyzer4.set_test_mode(false);
    let analysis4 = analyzer4.analyze()?;
    
    println!("  Warnings detected: {}", analysis4.security_warnings.len());
    if analysis4.security_warnings.is_empty() {
        println!("  ✅ PASSED: Internal call correctly identified as safe");
    } else {
        println!("  ❌ FAILED: Internal call flagged as vulnerable (false positive)");
    }
    
    println!("\n📊 Summary:");
    let total_tests = 4;
    let mut passed = 0;
    
    if analysis.security_warnings.is_empty() { passed += 1; }
    if analysis2.security_warnings.is_empty() { passed += 1; }  
    if !analysis3.security_warnings.is_empty() { passed += 1; }
    if analysis4.security_warnings.is_empty() { passed += 1; }
    
    println!("  Tests passed: {}/{}", passed, total_tests);
    println!("  False positive rate: {:.1}%", ((total_tests - passed) as f32 / total_tests as f32) * 100.0);
    
    if passed == total_tests {
        println!("  🎉 All tests passed! Advanced reentrancy detection is working correctly.");
    } else {
        println!("  ⚠️ Some tests failed. The detection algorithm may need refinement.");
    }
    
    Ok(())
}
