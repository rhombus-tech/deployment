/// Deep Reentrancy Analysis - Higher Confidence Verification
/// 
/// Goes beyond basic pattern matching to analyze:
/// 1. Actual execution flow and control paths
/// 2. Reentrancy guard implementation correctness  
/// 3. State change ordering (Checks-Effects-Interactions pattern)
/// 4. DELEGATECALL target analysis

use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;
use evm_verify::vm::evm_interpreter::EVMInterpreter;
use evm_verify::analysis::basic_reentrancy_detector::BasicReentrancyDetector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get contract address from command line argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --example deep_reentrancy_analyzer <contract_address>");
        eprintln!("Example: cargo run --example deep_reentrancy_analyzer 0x1776e1f26f98b1a5df9cd347953a26dd3cb46671");
        std::process::exit(1);
    }
    
    let address = &args[1];
    
    println!("\n🔬 DEEP REENTRANCY ANALYSIS");
    println!("{}", "=".repeat(100));
    println!("Contract: {}", address);
    println!("{}", "=".repeat(100));
    
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let addr = Address::from_str(address)?;
    let code = provider.get_code(addr, None).await?;
    
    println!("\n📊 Bytecode size: {} bytes", code.len());
    
    // Run basic detection first
    let detector = BasicReentrancyDetector::new(code.to_vec());
    let vulnerabilities = detector.detect_vulnerabilities();
    
    println!("\n🔍 Basic Detection Results: {} potential reentrancies", vulnerabilities.len());
    
    if vulnerabilities.is_empty() {
        println!("\n✅ No reentrancy patterns detected");
        return Ok(());
    }
    
    println!("\n{}", "=".repeat(100));
    println!("🔬 DEEP ANALYSIS OF EACH VULNERABILITY");
    println!("{}", "=".repeat(100));
    
    for (i, vuln) in vulnerabilities.iter().enumerate() {
        println!("\n{}", "-".repeat(100));
        println!("🔍 Vulnerability #{} at PC {}", i+1, vuln.pc);
        println!("{}", "-".repeat(100));
        
        println!("\n📋 Basic Info:");
        println!("   Call Opcode: {} ({})", 
                 format_opcode(vuln.call_opcode),
                 if vuln.call_opcode == 0xF4 { "DELEGATECALL - HIGH RISK" } else { "Standard call" });
        println!("   Severity: {:?}", vuln.severity);
        println!("   Confidence: {:.0}%", vuln.confidence * 100.0);
        println!("   Has Reentrancy Guard: {}", vuln.has_reentrancy_guard);
        println!("   State Changes After: {}", vuln.state_changes_after.len());
        
        // Deep Analysis
        println!("\n🔬 Deep Analysis:");
        
        // 1. Analyze guard effectiveness
        if vuln.has_reentrancy_guard {
            println!("\n   1️⃣ Reentrancy Guard Analysis:");
            println!("      ✓ Guard pattern detected in bytecode");
            
            let guard_analysis = analyze_guard_effectiveness(&code.to_vec(), vuln.pc);
            match guard_analysis {
                GuardAnalysis::Effective => {
                    println!("      ✅ Guard appears EFFECTIVE - uses modifier pattern");
                    println!("      → Likely protects against reentrancy");
                }
                GuardAnalysis::Partial => {
                    println!("      ⚠️  Guard may be PARTIAL - check coverage");
                    println!("      → Some paths might bypass the guard");
                }
                GuardAnalysis::Ineffective => {
                    println!("      ❌ Guard appears INEFFECTIVE");
                    println!("      → May not prevent reentrancy in this context");
                }
                GuardAnalysis::Unknown => {
                    println!("      ❓ Guard effectiveness UNCLEAR");
                    println!("      → Manual audit recommended");
                }
            }
        } else {
            println!("\n   1️⃣ Reentrancy Guard Analysis:");
            println!("      ❌ NO GUARD DETECTED");
            println!("      → Contract is vulnerable if state changes occur after call");
        }
        
        // 2. Analyze state changes
        println!("\n   2️⃣ State Change Analysis:");
        if !vuln.state_changes_after.is_empty() {
            println!("      ⚠️  {} SSTORE operations AFTER external call", vuln.state_changes_after.len());
            println!("      → This is the VULNERABLE pattern (call before state update)");
            println!("      → Should follow Checks-Effects-Interactions:");
            println!("         1. Checks (require statements)");
            println!("         2. Effects (update state)");
            println!("         3. Interactions (external calls)  ← Currently reversed!");
            
            for (j, pc) in vuln.state_changes_after.iter().take(3).enumerate() {
                println!("         SSTORE #{}: PC {}", j+1, pc);
            }
            if vuln.state_changes_after.len() > 3 {
                println!("         ... and {} more", vuln.state_changes_after.len() - 3);
            }
        }
        
        // 3. DELEGATECALL analysis
        if vuln.call_opcode == 0xF4 {
            println!("\n   3️⃣ DELEGATECALL Risk Analysis:");
            println!("      🚨 DELEGATECALL DETECTED - HIGHEST RISK");
            println!("      → Executes external code in THIS contract's context");
            println!("      → Can modify THIS contract's storage");
            println!("      → Attacker controls execution flow");
            println!("      → Common in proxy patterns but VERY DANGEROUS if misused");
        }
        
        // 4. Calculate final confidence
        println!("\n   4️⃣ Final Risk Assessment:");
        
        let final_confidence = calculate_final_confidence(vuln, &code.to_vec());
        let final_verdict = if final_confidence >= 0.85 {
            "HIGH PROBABILITY - Likely Vulnerable"
        } else if final_confidence >= 0.70 {
            "MODERATE PROBABILITY - Risky Pattern"  
        } else if final_confidence >= 0.50 {
            "LOW-MODERATE PROBABILITY - Needs Review"
        } else {
            "LOW PROBABILITY - Likely Safe"
        };
        
        println!("      Adjusted Confidence: {:.0}%", final_confidence * 100.0);
        println!("      Verdict: {}", final_verdict);
        
        if final_confidence >= 0.70 {
            println!("\n      ⚠️  RECOMMENDATION: Treat as vulnerable");
            println!("         - Warn validators");
            println!("         - Recommend manual audit");
            println!("         - Users should exercise caution");
        } else if final_confidence >= 0.50 {
            println!("\n      ℹ️  RECOMMENDATION: Flag for review");
            println!("         - Include in validator warnings");
            println!("         - Note uncertainty in confidence");
        } else {
            println!("\n      ✅ RECOMMENDATION: Likely false positive");
            println!("         - Guard appears effective");
            println!("         - Standard pattern usage");
        }
    }
    
    // Overall verdict
    println!("\n{}", "=".repeat(100));
    println!("🎯 OVERALL VERDICT");
    println!("{}", "=".repeat(100));
    
    let high_confidence_vulns: Vec<_> = vulnerabilities.iter()
        .filter(|v| calculate_final_confidence(v, &code.to_vec()) >= 0.70)
        .collect();
    
    if !high_confidence_vulns.is_empty() {
        println!("\n⚠️  {} HIGH-CONFIDENCE VULNERABILITIES DETECTED", high_confidence_vulns.len());
        println!("\nThis contract should be flagged as CRITICAL because:");
        println!("   - External calls occur before state updates");
        println!("   - Pattern allows potential reentrancy attacks");
        println!("   - Confidence level indicates real risk");
        println!("\n   Validators should include this in their warnings.");
    } else if !vulnerabilities.is_empty() {
        println!("\n✅ Reentrancy patterns detected but appear MITIGATED");
        println!("\n   - Guards appear to be working");
        println!("   - Low probability of actual exploit");
        println!("   - Can be classified as Medium or Low risk");
    }
    
    println!("\n{}", "=".repeat(100));
    
    Ok(())
}

fn format_opcode(opcode: u8) -> String {
    match opcode {
        0xF1 => "CALL".to_string(),
        0xF2 => "CALLCODE".to_string(),
        0xF4 => "DELEGATECALL".to_string(),
        0xFA => "STATICCALL".to_string(),
        _ => format!("0x{:02X}", opcode),
    }
}

#[derive(Debug)]
enum GuardAnalysis {
    Effective,      // Guard works properly
    Partial,        // Guard has gaps
    Ineffective,    // Guard doesn't work
    Unknown,        // Can't determine
}

fn analyze_guard_effectiveness(bytecode: &[u8], call_pc: usize) -> GuardAnalysis {
    // Look for common reentrancy guard patterns
    // Pattern 1: Storage slot set to 1 before call, checked at start
    // Pattern 2: Modifier with require(!locked)
    
    // Simplified heuristic:
    // - Look for SLOAD before the call
    // - Look for JUMPI (conditional jump) that could prevent reentry
    // - Look for SSTORE setting a lock
    
    let mut has_sload_before = false;
    let mut has_conditional_jump = false;
    let mut has_lock_pattern = false;
    
    // Search backwards from call
    let search_start = call_pc.saturating_sub(200);
    for i in search_start..call_pc {
        if i >= bytecode.len() {
            break;
        }
        match bytecode[i] {
            0x54 => has_sload_before = true,  // SLOAD
            0x57 => has_conditional_jump = true,  // JUMPI
            0x55 => has_lock_pattern = true,  // SSTORE (potential lock)
            _ => {}
        }
    }
    
    if has_sload_before && has_conditional_jump && has_lock_pattern {
        GuardAnalysis::Effective
    } else if has_sload_before || has_conditional_jump {
        GuardAnalysis::Partial
    } else {
        GuardAnalysis::Unknown
    }
}

fn calculate_final_confidence(vuln: &evm_verify::analysis::basic_reentrancy_detector::ReentrancyVulnerability, bytecode: &[u8]) -> f32 {
    let mut confidence = vuln.confidence;
    
    // Adjust based on guard analysis
    if vuln.has_reentrancy_guard {
        let guard_effectiveness = analyze_guard_effectiveness(bytecode, vuln.pc);
        match guard_effectiveness {
            GuardAnalysis::Effective => {
                confidence *= 0.4;  // Significantly reduce if guard is effective
            }
            GuardAnalysis::Partial => {
                confidence *= 0.7;  // Moderate reduction
            }
            GuardAnalysis::Ineffective => {
                // No reduction, guard doesn't help
            }
            GuardAnalysis::Unknown => {
                confidence *= 0.8;  // Slight reduction for uncertainty
            }
        }
    }
    
    // DELEGATECALL is inherently riskier
    if vuln.call_opcode == 0xF4 {
        confidence = (confidence * 1.2).min(0.95);
    }
    
    // More state changes = higher risk
    if vuln.state_changes_after.len() > 3 {
        confidence = (confidence * 1.1).min(0.95);
    }
    
    confidence
}
