/// Smoke test for the 10 new deep analysis gap fill analyzers
/// Verifies they instantiate and run without panicking

use evm_verify::analysis::{
    flash_mint_provider_detector::FlashMintProviderDetector,
    perpetuals_funding_detector::PerpetualsFundingDetector,
    soulbound_token_detector::SoulboundTokenDetector,
    checkpoint_vote_detector::CheckpointVoteDetector,
    stale_state_upgrade_detector::StaleStateUpgradeDetector,
    l2_timestamp_dependency_detector::L2TimestampDependencyDetector,
    collateral_ratio_detector::CollateralRatioDetector,
    curve_readonly_reentrancy_detector::CurveReadOnlyReentrancyDetector,
    balancer_weight_detector::BalancerWeightDetector,
    options_greeks_detector::OptionsGreeksDetector,
};

#[test]
fn test_all_new_analyzers_instantiate() {
    let bytecode = vec![0x60, 0x80, 0x60, 0x40, 0x52];
    
    // Flash Mint Provider
    let detector = FlashMintProviderDetector::new(bytecode.clone());
    let _results = detector.detect_vulnerabilities();
    
    // Perpetuals Funding
    let detector = PerpetualsFundingDetector::new(bytecode.clone());
    let _results = detector.detect_vulnerabilities();
    
    // Soulbound Token
    let detector = SoulboundTokenDetector::new(bytecode.clone());
    let _results = detector.detect_vulnerabilities();
    
    // Checkpoint Vote
    let detector = CheckpointVoteDetector::new(bytecode.clone());
    let _results = detector.detect_vulnerabilities();
    
    // Stale State Upgrade
    let detector = StaleStateUpgradeDetector::new(bytecode.clone());
    let _results = detector.detect_vulnerabilities();
    
    // L2 Timestamp Dependency
    let detector = L2TimestampDependencyDetector::new(bytecode.clone());
    let _results = detector.detect_vulnerabilities();
    
    // Collateral Ratio
    let detector = CollateralRatioDetector::new(bytecode.clone());
    let _results = detector.detect_vulnerabilities();
    
    // Curve Read-Only Reentrancy
    let detector = CurveReadOnlyReentrancyDetector::new(bytecode.clone());
    let _results = detector.detect_vulnerabilities();
    
    // Balancer Weight
    let detector = BalancerWeightDetector::new(bytecode.clone());
    let _results = detector.detect_vulnerabilities();
    
    // Options Greeks
    let detector = OptionsGreeksDetector::new(bytecode.clone());
    let _results = detector.detect_vulnerabilities();
    
    println!("✅ All 10 new analyzers instantiated and ran successfully!");
}

#[test]
fn test_flash_mint_provider_detection() {
    // EIP-3156 flashLoan function with no fee
    let bytecode = vec![
        0x5c, 0xff, 0xe9, 0xde, // flashLoan selector
        0xFA, // STATICCALL
        0x00, // No fee calculation
    ];
    
    let detector = FlashMintProviderDetector::new(bytecode);
    let vulns = detector.detect_vulnerabilities();
    
    // Should detect missing fee enforcement
    assert!(!vulns.is_empty(), "Should detect flash mint provider issues");
    println!("✅ Flash mint provider detection working");
}

#[test]
fn test_soulbound_token_detection() {
    // EIP-5192 locked() with working transfer()
    let bytecode = vec![
        0xcf, 0x30, 0x90, 0x12, // locked() selector
        0xa9, 0x05, 0x9c, 0xbb, // transfer() selector
        0x55, // SSTORE (executes transfer)
    ];
    
    let detector = SoulboundTokenDetector::new(bytecode);
    let vulns = detector.detect_vulnerabilities();
    
    assert!(!vulns.is_empty(), "Should detect SBT transfer not disabled");
    println!("✅ Soulbound token detection working");
}

#[test]
fn test_l2_timestamp_dependency() {
    // Using timestamp for randomness
    let bytecode = vec![
        0x42, // TIMESTAMP
        0x20, // KECCAK256 (randomness)
    ];
    
    let detector = L2TimestampDependencyDetector::new(bytecode);
    let vulns = detector.detect_vulnerabilities();
    
    assert!(!vulns.is_empty(), "Should detect L2 timestamp manipulation risk");
    println!("✅ L2 timestamp dependency detection working");
}

#[test]
fn test_comprehensive_analyzer_includes_new_detectors() {
    use evm_verify::analysis::comprehensive_analyzer::ComprehensiveAnalyzerBuilder;
    
    // Simple bytecode
    let bytecode = vec![
        0x60, 0x80, 0x60, 0x40, 0x52, // Constructor
        0x5c, 0xff, 0xe9, 0xde, // flashLoan
        0xcf, 0x30, 0x90, 0x12, // locked
    ];
    
    let result = ComprehensiveAnalyzerBuilder::new(bytecode)
        .build()
        .analyze();
    
    // Verify new fields exist in result
    let _flash_mint = &result.flash_mint_provider_vulnerabilities;
    let _perpetuals = &result.perpetuals_funding_vulnerabilities;
    let _soulbound = &result.soulbound_token_vulnerabilities;
    let _checkpoint = &result.checkpoint_vote_vulnerabilities;
    let _stale_state = &result.stale_state_upgrade_vulnerabilities;
    let _l2_timestamp = &result.l2_timestamp_vulnerabilities;
    let _collateral = &result.collateral_ratio_vulnerabilities;
    let _curve = &result.curve_readonly_reentrancy_vulnerabilities;
    let _balancer = &result.balancer_weight_vulnerabilities;
    let _options = &result.options_greeks_vulnerabilities;
    
    println!("✅ Comprehensive analyzer includes all 10 new detectors");
    println!("📊 Total vulnerabilities found: {}", result.total_vulnerabilities);
}
