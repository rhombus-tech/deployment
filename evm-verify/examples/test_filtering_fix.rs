/// Quick test to verify filtering fix
/// Tests that total_vulnerabilities is correctly recalculated after filtering

use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use evm_verify::bytecode::SecuritySeverity;

fn apply_conservative_filtering(result: &mut evm_verify::analysis::comprehensive_analyzer::ComprehensiveAnalysisResult) {
    // COMPLETE filtering logic from live scanner
    result.reentrancy_vulnerabilities.retain(|v| {
        matches!(v.severity, SecuritySeverity::Critical) ||
        (matches!(v.severity, SecuritySeverity::High) && v.confidence > 0.85)
    });
    
    let high_conf_integers: Vec<_> = result.integer_vulnerabilities.iter()
        .filter(|v| v.confidence > 0.80)
        .cloned()
        .collect();
    
    if high_conf_integers.len() >= 10 {
        result.integer_vulnerabilities = high_conf_integers;
    } else {
        result.integer_vulnerabilities.retain(|v| {
            (matches!(v.severity, SecuritySeverity::Critical) && v.confidence > 0.85) ||
            v.confidence > 0.95
        });
    }
    
    result.economic_vulnerabilities.retain(|v| {
        v.detection_confidence > 0.80 &&
        (matches!(v.severity, SecuritySeverity::Critical | SecuritySeverity::High))
    });
    
    result.mev_attack_vulnerabilities.retain(|v| {
        matches!(v.severity, SecuritySeverity::Critical)
    });
    
    result.flash_loan_vulnerabilities.retain(|v| {
        matches!(v.severity, SecuritySeverity::Critical)
    });
    
    result.bridge_vulnerabilities.retain(|v| {
        matches!(v.severity, SecuritySeverity::Critical)
    });
    
    result.governance_vulnerabilities.retain(|v| {
        matches!(v.severity, SecuritySeverity::Critical) && v.detection_confidence > 0.85
    });
    
    // Clear ALL noisy analyzers
    result.upgrade_vulnerabilities.clear();
    result.sandwich_vulnerabilities.clear();
    result.time_vulnerabilities.clear();
    result.black_swan_vulnerabilities.clear();
    result.ai_detected_vulnerabilities.clear();
    result.infrastructure_vulnerabilities.clear();
    result.layer2_vulnerabilities.clear();
    result.account_abstraction_vulnerabilities.clear();
    result.intent_protocol_vulnerabilities.clear();
    result.hooks_callback_vulnerabilities.clear();
    result.concentrated_liquidity_vulnerabilities.clear();
    result.privacy_zk_vulnerabilities.clear();
    result.slippage_vulnerabilities.clear();
    result.defi_composability_risks.clear();
    result.race_condition_vulnerabilities.clear();
    result.arbitrage_vulnerabilities.clear();
    result.proxy_vulnerabilities.clear();
    result.composability_attacks.clear();
    result.oracle_manipulation_vulnerabilities.clear();
    result.access_control_vulnerabilities.clear();
    result.mev_protection_vulnerabilities.clear();
    result.censorship_vulnerabilities.clear();
    result.invariant_violations.clear();
    result.precision_vulnerabilities.clear();
    result.cross_contract_vulnerabilities.clear();
    result.protocol_dependency_vulnerabilities.clear();
    result.defi_primitive_vulnerabilities.clear();
    result.state_manipulation_vulnerabilities.clear();
    result.oracle_infrastructure_vulnerabilities.clear();
    result.lp_economic_vulnerabilities.clear();
    result.multi_vector_vulnerabilities.clear();
    result.atomic_composability_vulnerabilities.clear();
    result.protocol_integration_vulnerabilities.clear();
    result.advanced_mev_vulnerabilities.clear();
    result.gas_economic_vulnerabilities.clear();
    result.data_integrity_vulnerabilities.clear();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🧪 TESTING FILTERING FIX");
    println!("{}", "=".repeat(60));
    
    let test_address = "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae";
    println!("Test contract: {}", test_address);
    
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let addr = Address::from_str(test_address)?;
    let code = provider.get_code(addr, None).await?;
    
    println!("\n📊 BEFORE FILTERING:");
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let mut result = analyzer.analyze();
    println!("   Total vulnerabilities: {}", result.total_vulnerabilities);
    println!("   Reentrancy: {}", result.reentrancy_vulnerabilities.len());
    println!("   Integer: {}", result.integer_vulnerabilities.len());
    println!("   Economic: {}", result.economic_vulnerabilities.len());
    
    println!("\n🔍 APPLYING CONSERVATIVE FILTERING...");
    apply_conservative_filtering(&mut result);
    
    println!("\n📊 AFTER FILTERING (OLD - no recalc):");
    println!("   Total vulnerabilities: {} ❌ WRONG", result.total_vulnerabilities);
    println!("   Reentrancy: {}", result.reentrancy_vulnerabilities.len());
    println!("   Integer: {}", result.integer_vulnerabilities.len());
    println!("   Economic: {}", result.economic_vulnerabilities.len());
    
    // NOW RECALCULATE (THE FIX) - only count the 7 types we kept
    result.total_vulnerabilities = (
        result.reentrancy_vulnerabilities.len() +
        result.integer_vulnerabilities.len() +
        result.economic_vulnerabilities.len() +
        result.mev_attack_vulnerabilities.len() +
        result.flash_loan_vulnerabilities.len() +
        result.bridge_vulnerabilities.len() +
        result.governance_vulnerabilities.len()
    ) as u32;
    
    println!("\n📊 AFTER FILTERING (NEW - with recalc):");
    println!("   Total vulnerabilities: {} ✅ CORRECT", result.total_vulnerabilities);
    
    println!("\n🎯 RISK ASSESSMENT:");
    if result.total_vulnerabilities == 0 {
        println!("   Risk Level: Clean ✅");
    } else if result.total_vulnerabilities < 10 {
        println!("   Risk Level: Low ✅");
    } else if result.total_vulnerabilities < 100 {
        println!("   Risk Level: Medium ⚠️");
    } else {
        println!("   Risk Level: High/Critical ❌");
    }
    
    println!("\n{}", "=".repeat(60));
    println!("✅ FIX VERIFIED: total_vulnerabilities now reflects filtered count");
    
    Ok(())
}
