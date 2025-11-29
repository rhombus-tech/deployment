/// Scan a specific block to test if we're still detecting the same contracts
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{BlockId, BlockNumber};
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use evm_verify::bytecode::SecuritySeverity;

fn apply_conservative_filtering(result: &mut evm_verify::analysis::comprehensive_analyzer::ComprehensiveAnalysisResult) {
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
    
    // Clear all noisy analyzers
    result.upgrade_vulnerabilities.clear();
    result.sandwich_vulnerabilities.clear();
    result.time_vulnerabilities.clear();
    result.cross_contract_vulnerabilities.clear();
    result.protocol_dependency_vulnerabilities.clear();
    result.defi_primitive_vulnerabilities.clear();
    result.state_manipulation_vulnerabilities.clear();
    result.oracle_infrastructure_vulnerabilities.clear();
    result.lp_economic_vulnerabilities.clear();
    result.black_swan_vulnerabilities.clear();
    result.multi_vector_vulnerabilities.clear();
    result.ai_detected_vulnerabilities.clear();
    result.infrastructure_vulnerabilities.clear();
    result.atomic_composability_vulnerabilities.clear();
    result.protocol_integration_vulnerabilities.clear();
    result.advanced_mev_vulnerabilities.clear();
    result.gas_economic_vulnerabilities.clear();
    result.data_integrity_vulnerabilities.clear();
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
    
    result.total_vulnerabilities = 
        result.reentrancy_vulnerabilities.len() as u32 +
        result.integer_vulnerabilities.len() as u32 +
        result.economic_vulnerabilities.len() as u32 +
        result.mev_attack_vulnerabilities.len() as u32 +
        result.flash_loan_vulnerabilities.len() as u32 +
        result.bridge_vulnerabilities.len() as u32 +
        result.governance_vulnerabilities.len() as u32;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 TESTING CONTRACT WITH FILTERING");
    println!("Contract: 0x3314fb492a5d205a601f2a0521fafbd039502fc3\n");
    
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    // Test this specific contract
    let test_addresses = vec![
        "0x3314fb492a5d205a601f2a0521fafbd039502fc3",
    ];
    
    for addr_str in test_addresses {
        println!("Testing: {}", addr_str);
        
        let addr: ethers::types::Address = addr_str.parse()?;
        let code = provider.get_code(addr, None).await?;
        
        if code.is_empty() {
            println!("  ❌ No code\n");
            continue;
        }
        
        let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
        let mut result = analyzer.analyze();
        
        println!("  Before filtering: {} findings", result.total_vulnerabilities);
        
        apply_conservative_filtering(&mut result);
        
        println!("  After filtering: {} findings", result.total_vulnerabilities);
        
        // Determine risk level using same logic as live scanner
        let high_conf_integers: Vec<_> = result.integer_vulnerabilities.iter()
            .filter(|v| v.confidence >= 0.85)
            .collect();
        let density = if result.integer_vulnerabilities.len() > 0 {
            (high_conf_integers.len() as f32 / result.integer_vulnerabilities.len() as f32) * 100.0
        } else {
            0.0
        };
        let has_critical_governance = result.governance_vulnerabilities.iter()
            .any(|v| matches!(v.severity, SecuritySeverity::Critical));
        let has_critical_integer = 
            (high_conf_integers.len() >= 20 && density >= 10.0) ||
            (high_conf_integers.len() >= 25 && density >= 9.0) ||
            (has_critical_governance && high_conf_integers.len() >= 20);
        
        let risk = if result.total_vulnerabilities == 0 {
            "Clean"
        } else if has_critical_integer {
            "Critical"
        } else if result.total_vulnerabilities < 10 {
            "Low"
        } else if result.total_vulnerabilities < 100 {
            "Medium"  
        } else {
            "High/Critical"
        };
        
        println!("  Risk Level: {}", risk);
        
        if result.total_vulnerabilities > 0 {
            println!("  Breakdown:");
            if result.reentrancy_vulnerabilities.len() > 0 {
                println!("    - Reentrancy: {}", result.reentrancy_vulnerabilities.len());
            }
            if result.integer_vulnerabilities.len() > 0 {
                println!("    - Integer: {}", result.integer_vulnerabilities.len());
            }
            if result.economic_vulnerabilities.len() > 0 {
                println!("    - Economic: {}", result.economic_vulnerabilities.len());
            }
            if result.mev_attack_vulnerabilities.len() > 0 {
                println!("    - MEV: {}", result.mev_attack_vulnerabilities.len());
            }
            if result.flash_loan_vulnerabilities.len() > 0 {
                println!("    - Flash Loan: {}", result.flash_loan_vulnerabilities.len());
            }
            if result.bridge_vulnerabilities.len() > 0 {
                println!("    - Bridge: {}", result.bridge_vulnerabilities.len());
            }
            if result.governance_vulnerabilities.len() > 0 {
                println!("    - Governance: {}", result.governance_vulnerabilities.len());
            }
        }
        
        println!();
    }
    
    Ok(())
}
