// Conservative analyzer configuration for production use
// Only flags HIGH CONFIDENCE vulnerabilities

use super::comprehensive_analyzer::{ComprehensiveSecurityAnalyzer, ComprehensiveAnalysisResult};
use super::advanced_reentrancy_detector::AdvancedReentrancyVulnerability;
use super::integer_safety_detector::IntegerVulnerability;

/// Analyzes bytecode with conservative settings to minimize false positives
pub fn analyze_conservative(bytecode: &[u8]) -> FilteredAnalysisResult {
    let analyzer = ComprehensiveSecurityAnalyzer::new(bytecode.to_vec());
    let full_result = analyzer.analyze();
    
    // FOUNDATIONAL VULNERABILITIES: Reentrancy and Integer issues (HIGH PRIORITY)
    // Reentrancy: Flag High+ severity with 85%+ confidence OR Critical with any confidence
    let filtered_reentrancy: Vec<_> = full_result.reentrancy_vulnerabilities
        .into_iter()
        .filter(|v| {
            matches!(v.severity, crate::bytecode::SecuritySeverity::Critical) ||
            (matches!(v.severity, crate::bytecode::SecuritySeverity::High) && v.confidence > 0.85)
        })
        .collect();
    
    // Integer: Only flag if BOTH high severity AND high confidence
    // This avoids false positives from benign arithmetic in well-audited DeFi contracts
    // while still catching real vulnerabilities like BeautyChain's batchOverflow
    let filtered_integer: Vec<_> = full_result.integer_vulnerabilities
        .into_iter()
        .filter(|v| {
            // Critical severity with 85%+ confidence (catches real exploits)
            (matches!(v.severity, crate::bytecode::SecuritySeverity::Critical) && v.confidence > 0.85) ||
            // OR very high confidence (95%+) regardless of severity (in-loop arithmetic)
            v.confidence > 0.95
        })
        .collect();
    
    // ULTRA-CONSERVATIVE: Only flag Critical/High severity with high confidence (90%+)
    let filtered_economic: Vec<_> = full_result.economic_vulnerabilities
        .into_iter()
        .filter(|v| {
            v.detection_confidence > 0.90 && 
            (matches!(v.severity, crate::bytecode::SecuritySeverity::Critical) ||
             matches!(v.severity, crate::bytecode::SecuritySeverity::High))
        })
        .collect();
    
    // Sandwich: DISABLED - too many false positives on DEX contracts
    // DEX functionality is not a vulnerability; sandwich attacks are user-level threats
    let filtered_sandwich: Vec<_> = vec![];
    
    // MEV: Only Critical
    let filtered_mev: Vec<_> = full_result.mev_attack_vulnerabilities
        .into_iter()
        .filter(|v| {
            matches!(v.severity, crate::bytecode::SecuritySeverity::Critical)
        })
        .collect();
    
    // Flash Loan: Only Critical
    let filtered_flashloan: Vec<_> = full_result.flash_loan_vulnerabilities
        .into_iter()
        .filter(|v| {
            matches!(v.severity, crate::bytecode::SecuritySeverity::Critical)
        })
        .collect();
    
    let conservative_total = filtered_reentrancy.len()
        + filtered_integer.len()
        + filtered_economic.len()
        + filtered_sandwich.len()
        + filtered_mev.len()
        + filtered_flashloan.len();
    
    FilteredAnalysisResult {
        total_vulnerabilities: conservative_total as u32,
        critical_count: count_critical_filtered(&filtered_reentrancy, &filtered_integer, &filtered_economic, &filtered_sandwich),
        high_count: count_high_filtered(&filtered_reentrancy, &filtered_integer, &filtered_economic, &filtered_sandwich),
        
        reentrancy_vulnerabilities: filtered_reentrancy,
        integer_vulnerabilities: filtered_integer,
        economic_vulnerabilities: filtered_economic,
        sandwich_vulnerabilities: filtered_sandwich,
        mev_attack_vulnerabilities: filtered_mev,
        flash_loan_vulnerabilities: filtered_flashloan,
        
        // Exclude noisy analyzers that produce false positives
        upgrade_vulnerabilities: vec![],  // Too noisy - flags legitimate proxies
        time_vulnerabilities: vec![],     // Too noisy - flags legitimate timelocks
        black_swan_vulnerabilities: vec![], // Too speculative
        ai_detected_vulnerabilities: vec![], // Too experimental
        infrastructure_vulnerabilities: vec![], // Too broad
    }
}

fn count_critical_filtered(
    reentrancy: &[AdvancedReentrancyVulnerability],
    integer: &[IntegerVulnerability],
    economic: &[super::economic_attacks::EconomicVulnerability],
    sandwich: &[super::sandwich_attacks::SandwichVulnerability],
) -> u32 {
    reentrancy.iter()
        .filter(|v| matches!(v.severity, crate::bytecode::SecuritySeverity::Critical))
        .count() as u32
    + integer.iter()
        .filter(|v| matches!(v.severity, crate::bytecode::SecuritySeverity::Critical))
        .count() as u32
    + economic.iter()
        .filter(|v| matches!(v.severity, crate::bytecode::SecuritySeverity::Critical))
        .count() as u32
    + sandwich.iter()
        .filter(|v| matches!(v.severity, crate::bytecode::SecuritySeverity::Critical))
        .count() as u32
}

fn count_high_filtered(
    reentrancy: &[AdvancedReentrancyVulnerability],
    integer: &[IntegerVulnerability],
    economic: &[super::economic_attacks::EconomicVulnerability],
    sandwich: &[super::sandwich_attacks::SandwichVulnerability],
) -> u32 {
    reentrancy.iter()
        .filter(|v| matches!(v.severity, crate::bytecode::SecuritySeverity::High))
        .count() as u32
    + integer.iter()
        .filter(|v| matches!(v.severity, crate::bytecode::SecuritySeverity::High))
        .count() as u32
    + economic.iter()
        .filter(|v| matches!(v.severity, crate::bytecode::SecuritySeverity::High))
        .count() as u32
    + sandwich.iter()
        .filter(|v| matches!(v.severity, crate::bytecode::SecuritySeverity::High))
        .count() as u32
}

// High confidence filters
fn is_high_confidence_economic(v: &super::economic_attacks::EconomicVulnerability) -> bool {
    // Only flag if detection confidence > 0.8
    v.detection_confidence > 0.8
}

#[derive(Debug)]
pub struct FilteredAnalysisResult {
    pub total_vulnerabilities: u32,
    pub critical_count: u32,
    pub high_count: u32,
    // Foundational Solidity vulnerabilities (highest priority, false positive reduced)
    pub reentrancy_vulnerabilities: Vec<AdvancedReentrancyVulnerability>,
    pub integer_vulnerabilities: Vec<IntegerVulnerability>,
    // DeFi and protocol vulnerabilities
    pub economic_vulnerabilities: Vec<super::economic_attacks::EconomicVulnerability>,
    pub sandwich_vulnerabilities: Vec<super::sandwich_attacks::SandwichVulnerability>,
    pub mev_attack_vulnerabilities: Vec<super::mev_attack_chain_detector::MevAttackVulnerability>,
    pub flash_loan_vulnerabilities: Vec<super::multi_protocol_flashloan_detector::FlashLoanVulnerability>,
    pub upgrade_vulnerabilities: Vec<super::upgradeable_risks::UpgradeableVulnerability>,
    pub time_vulnerabilities: Vec<super::time_attacks::TimeVulnerability>,
    pub black_swan_vulnerabilities: Vec<super::black_swan_simulator::BlackSwanVulnerability>,
    pub ai_detected_vulnerabilities: Vec<super::ai_adaptive_attack_detector::AIDetectedVulnerability>,
    pub infrastructure_vulnerabilities: Vec<super::infrastructure_risk_analyzer::InfrastructureVulnerability>,
}
