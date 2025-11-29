/// Example: Using improved analyzers with false positive reduction

use evm_verify::analysis::{
    basic_reentrancy_detector::BasicReentrancyDetector,
    advanced_reentrancy_detector::AdvancedReentrancyDetector,
    safe_patterns::SafePatternDatabase,
    confidence_scorer::{ConfidenceScorer, CodeQualitySignals},
    false_positive_tracker::FalsePositiveTracker,
};

fn main() {
    let bytecode = vec![
        // Example: OpenZeppelin ReentrancyGuard protected code
        0x54, 0x60, 0x02, 0x14, // SLOAD, PUSH1 2, EQ (guard check)
        0x15, 0x57, // ISZERO, JUMPI (revert if locked)
        0xF1, // CALL (external call)
        0x55, // SSTORE (state change after)
    ];
    
    println!("═══════════════════════════════════════");
    println!("COMPARISON: Basic vs Advanced Detection");
    println!("═══════════════════════════════════════\n");
    
    // BEFORE: Basic detector (high false positives)
    println!("BASIC REENTRANCY DETECTOR:");
    let basic = BasicReentrancyDetector::new(bytecode.clone());
    let basic_results = basic.detect_vulnerabilities();
    
    for vuln in &basic_results {
        println!("  🔴 Found: {}", vuln.description);
        println!("      Confidence: {:.0}%", vuln.confidence * 100.0);
        println!("      Severity: {:?}", vuln.severity);
    }
    
    // AFTER: Advanced detector (low false positives)
    println!("\nADVANCED REENTRANCY DETECTOR:");
    let advanced = AdvancedReentrancyDetector::new(bytecode.clone());
    let advanced_results = advanced.detect_vulnerabilities();
    
    if advanced_results.is_empty() {
        println!("  ✅ No vulnerabilities (protection detected)");
    } else {
        for vuln in &advanced_results {
            if vuln.is_likely_false_positive {
                println!("  🟡 Likely False Positive: {}", vuln.description);
            } else {
                println!("  🔴 Real Vulnerability: {}", vuln.description);
            }
            println!("      Confidence: {:.0}%", vuln.confidence * 100.0);
            println!("      Protections: {:?}", vuln.protection_mechanisms);
        }
    }
    
    // Using SafePatternDatabase
    println!("\nSAFE PATTERN DETECTION:");
    let safe_db = SafePatternDatabase::new();
    if let Some(pattern) = safe_db.matches(&bytecode, 0) {
        println!("  ✅ Matches: {}", pattern.name);
        println!("      Confidence reduction: {:.0}%", pattern.confidence_reduction * 100.0);
    }
    
    // Using ConfidenceScorer
    println!("\nCONFIDENCE SCORING:");
    let code_quality = CodeQualitySignals::from_bytecode(&bytecode);
    let final_confidence = ConfidenceScorer::score(
        0.95, // base confidence
        true, // has protection
        0.9,  // protection strength (90%)
        0.3,  // historical 30% FP rate
        &code_quality,
    );
    
    println!("  Base confidence: 95%");
    println!("  After adjustments: {:.0}%", final_confidence * 100.0);
    println!("  Should report? {}", ConfidenceScorer::should_report(final_confidence, "Critical"));
    
    // Using FalsePositiveTracker
    println!("\nFALSE POSITIVE TRACKING:");
    let mut tracker = FalsePositiveTracker::new();
    
    // Simulate user feedback
    tracker.report_false_positive("BasicReentrancyDetector", bytecode[0..8].to_vec());
    tracker.report_false_positive("BasicReentrancyDetector", bytecode[0..8].to_vec());
    tracker.report_true_positive("AdvancedReentrancyDetector");
    
    println!("{}", tracker.generate_report());
    
    // Check if current bytecode matches known FP
    if let Some(penalty) = tracker.check_pattern(&bytecode) {
        println!("  ⚠️  Matches known false positive pattern");
        println!("      Confidence penalty: {:.0}%", penalty * 100.0);
    }
}
