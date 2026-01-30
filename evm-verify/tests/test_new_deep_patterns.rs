/// Integration test for 7 new deep bytecode-level pattern analyzers
use evm_verify::analysis::{
    assert_require_misuse_detector::AssertRequireMisuseDetector,
    unchecked_lowlevel_call_detector::UncheckedLowLevelCallDetector,
    selfbalance_reentrancy_detector::SelfBalanceReentrancyDetector,
    proxy_selfdestruct_detector::ProxySelfdestructDetector,
    block_number_equality_detector::BlockNumberEqualityDetector,
    tx_gasprice_dependence_detector::TxGaspriceDependenceDetector,
    encodepacked_collision_detector::EncodePackedCollisionDetector,
};

#[test]
fn test_assert_require_detector_instantiation() {
    // INVALID opcode (0xFE) - assert() in pre-0.8.0
    let bytecode = vec![0x60, 0x01, 0xFE, 0x00];
    let detector = AssertRequireMisuseDetector::new(bytecode);
    let vulns = detector.detect_vulnerabilities();
    assert!(!vulns.is_empty(), "Should detect INVALID opcode");
}

#[test]
fn test_unchecked_call_detector() {
    // CALL opcode (0xF1) without ISZERO check
    let bytecode = vec![0xF1, 0x50, 0x00]; // CALL, POP, STOP
    let detector = UncheckedLowLevelCallDetector::new(bytecode);
    let vulns = detector.detect_vulnerabilities();
    assert!(!vulns.is_empty(), "Should detect unchecked CALL");
}

#[test]
fn test_selfbalance_detector() {
    // BALANCE opcode (0x31)
    let bytecode = vec![0x31, 0x00];
    let detector = SelfBalanceReentrancyDetector::new(bytecode);
    let vulns = detector.detect_vulnerabilities();
    assert!(!vulns.is_empty(), "Should detect BALANCE usage");
}

#[test]
fn test_proxy_selfdestruct_detector() {
    // SELFDESTRUCT opcode (0xFF)
    let bytecode = vec![0xFF];
    let detector = ProxySelfdestructDetector::new(bytecode);
    let vulns = detector.detect_vulnerabilities();
    assert_eq!(vulns.len(), 1, "Should detect SELFDESTRUCT");
}

#[test]
fn test_block_number_equality_detector() {
    // NUMBER (0x43) followed by EQ (0x14)
    let bytecode = vec![0x43, 0x60, 0x01, 0x14]; // NUMBER, PUSH1 1, EQ
    let detector = BlockNumberEqualityDetector::new(bytecode);
    let vulns = detector.detect_vulnerabilities();
    assert!(!vulns.is_empty(), "Should detect block.number == pattern");
}

#[test]
fn test_tx_gasprice_detector() {
    // GASPRICE opcode (0x3A)
    let bytecode = vec![0x3A, 0x00];
    let detector = TxGaspriceDependenceDetector::new(bytecode);
    let vulns = detector.detect_vulnerabilities();
    assert_eq!(vulns.len(), 1, "Should detect GASPRICE usage");
}

#[test]
fn test_encodepacked_collision_detector() {
    // KECCAK256 opcode (0x20)
    let bytecode = vec![0x20, 0x00];
    let detector = EncodePackedCollisionDetector::new(bytecode);
    let vulns = detector.detect_vulnerabilities();
    assert!(!vulns.is_empty(), "Should detect hash computation");
}

#[test]
fn test_all_detectors_work_together() {
    // Bytecode with multiple patterns
    let bytecode = vec![
        0xFE, // INVALID (assert)
        0xF1, // CALL
        0x31, // BALANCE
        0xFF, // SELFDESTRUCT
        0x43, 0x14, // NUMBER, EQ
        0x3A, // GASPRICE
        0x20, // KECCAK256
    ];
    
    let assert_vuln = AssertRequireMisuseDetector::new(bytecode.clone()).detect_vulnerabilities();
    let call_vuln = UncheckedLowLevelCallDetector::new(bytecode.clone()).detect_vulnerabilities();
    let balance_vuln = SelfBalanceReentrancyDetector::new(bytecode.clone()).detect_vulnerabilities();
    let selfdestruct_vuln = ProxySelfdestructDetector::new(bytecode.clone()).detect_vulnerabilities();
    let block_vuln = BlockNumberEqualityDetector::new(bytecode.clone()).detect_vulnerabilities();
    let gasprice_vuln = TxGaspriceDependenceDetector::new(bytecode.clone()).detect_vulnerabilities();
    let encodepacked_vuln = EncodePackedCollisionDetector::new(bytecode.clone()).detect_vulnerabilities();
    
    assert!(!assert_vuln.is_empty(), "Assert detector works");
    assert!(!call_vuln.is_empty(), "Call detector works");
    assert!(!balance_vuln.is_empty(), "Balance detector works");
    assert!(!selfdestruct_vuln.is_empty(), "Selfdestruct detector works");
    assert!(!block_vuln.is_empty(), "Block number detector works");
    assert!(!gasprice_vuln.is_empty(), "Gasprice detector works");
    assert!(!encodepacked_vuln.is_empty(), "EncodePacked detector works");
}
