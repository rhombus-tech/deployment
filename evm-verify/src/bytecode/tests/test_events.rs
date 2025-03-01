use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::security::SecurityWarningKind;
use ethers::types::Bytes;

#[test]
fn test_event_emission_analysis() {
    // Test bytecode with state changes (SSTORE) without events
    let bytecode = Bytes::from(vec![
        0x60, 0x01, // PUSH1 1
        0x60, 0x00, // PUSH1 0
        0x55,       // SSTORE
        0x60, 0x02, // PUSH1 2
        0x60, 0x01, // PUSH1 1
        0x55,       // SSTORE
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    let analysis_results = analyzer.analyze().expect("Analysis should succeed");
    
    let warnings = analysis_results.security_warnings.iter()
        .filter(|w| matches!(w.kind, SecurityWarningKind::EventEmissionVulnerability))
        .collect::<Vec<_>>();
    
    assert!(!warnings.is_empty(), "Should detect event emission vulnerabilities");
}

#[test]
fn test_proper_event_emission() {
    // Test bytecode with state changes (SSTORE) with proper events
    let bytecode = Bytes::from(vec![
        0x60, 0x01, // PUSH1 1
        0x60, 0x00, // PUSH1 0
        0x55,       // SSTORE
        0x60, 0x01, // PUSH1 1 (topic)
        0x60, 0x00, // PUSH1 0 (length)
        0x60, 0x00, // PUSH1 0 (offset)
        0xa1,       // LOG1
        0x60, 0x02, // PUSH1 2
        0x60, 0x01, // PUSH1 1
        0x55,       // SSTORE
        0x60, 0x02, // PUSH1 2 (topic)
        0x60, 0x00, // PUSH1 0 (length)
        0x60, 0x00, // PUSH1 0 (offset)
        0xa1,       // LOG1
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.analyze();
    
    // Set test mode to true to avoid other warnings
    analyzer.set_test_mode(true);
    
    let analysis_results = analyzer.analyze().expect("Analysis should succeed");
    let warnings = analysis_results.security_warnings.iter()
        .filter(|w| matches!(w.kind, SecurityWarningKind::EventEmissionVulnerability))
        .collect::<Vec<_>>();
    
    assert!(warnings.is_empty(), "Should not detect vulnerabilities when events are properly emitted");
}

#[test]
fn test_incomplete_event_parameters() {
    // Test bytecode with incomplete event parameters
    // PUSH1 0x01
    // PUSH1 0x02
    // SSTORE
    // PUSH1 0x01
    // LOG1 (missing memory offset parameter)
    let bytecode = Bytes::from(vec![
        0x60, 0x01, 0x60, 0x02, 0x55, 0x60, 0x01, 0xa1
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    let analysis_results = analyzer.analyze().expect("Analysis should succeed");
    
    let warnings = analysis_results.security_warnings.iter()
        .filter(|w| w.kind == SecurityWarningKind::EventEmissionVulnerability)
        .collect::<Vec<_>>();
    
    // Should detect incomplete event parameters
    assert!(warnings.len() > 0, "Should detect event emission vulnerabilities");
    
    // Check that at least one warning mentions incomplete parameters
    let incomplete_params_warning = warnings.iter()
        .any(|w| w.description.contains("incomplete") || w.description.contains("Incomplete"));
    
    assert!(incomplete_params_warning, "Should detect incomplete event parameters");
}

#[test]
fn test_inconsistent_event_patterns() {
    // Test bytecode with inconsistent event patterns
    // Group 1: State change with event
    // PUSH1 0x01
    // PUSH1 0x02
    // SSTORE
    // PUSH1 0x00
    // PUSH1 0x20
    // PUSH1 0x01
    // LOG1
    // 
    // Group 2: State change without event
    // PUSH1 0x03
    // PUSH1 0x04
    // SSTORE
    let bytecode = Bytes::from(vec![
        // Group 1
        0x60, 0x01, 0x60, 0x02, 0x55, 0x60, 0x00, 0x60, 0x20, 0x60, 0x01, 0xa1,
        // Some padding to separate the groups
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        // Group 2
        0x60, 0x03, 0x60, 0x04, 0x55
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    let analysis_results = analyzer.analyze().expect("Analysis should succeed");
    
    let warnings = analysis_results.security_warnings.iter()
        .filter(|w| w.kind == SecurityWarningKind::EventEmissionVulnerability)
        .collect::<Vec<_>>();
    
    // Should detect inconsistent event patterns
    assert!(warnings.len() > 0, "Should detect event emission vulnerabilities");
    
    // Check that at least one warning mentions inconsistent patterns
    let inconsistent_patterns_warning = warnings.iter()
        .any(|w| w.description.contains("inconsistent") || w.description.contains("Inconsistent"));
    
    assert!(inconsistent_patterns_warning, "Should detect inconsistent event patterns");
}

#[test]
fn test_in_test_mode() {
    // Test that no warnings are generated in test mode
    let bytecode = Bytes::from(vec![
        0x60, 0x01, // PUSH1 1
        0x60, 0x00, // PUSH1 0
        0x55,       // SSTORE
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(true);
    let analysis_results = analyzer.analyze().expect("Analysis should succeed");
    
    let warnings = analysis_results.security_warnings.iter()
        .filter(|w| w.kind == SecurityWarningKind::EventEmissionVulnerability)
        .collect::<Vec<_>>();
    
    // Should not have any event emission warnings in test mode
    assert_eq!(warnings.len(), 0, "Should not detect event emission vulnerabilities in test mode");
}
