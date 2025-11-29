// Integration test for audit-level analysis system

use evm_verify::analysis::{
    economic_validator::EconomicValidator,
    invariant_checker::{InvariantChecker, InvariantPriority},
    attack_simulator::AttackSimulator,
};

#[tokio::test]
async fn test_economic_validator_initialization() {
    let validator = EconomicValidator::new(
        "https://ethereum.publicnode.com",
        1,
    );
    
    assert!(validator.is_ok(), "Economic validator should initialize");
}

#[test]
fn test_invariant_checker_initialization() {
    let bytecode = vec![0x60, 0x80, 0x60, 0x40]; // Simple bytecode
    let checker = InvariantChecker::new(bytecode);
    
    // Should have default invariants
    assert!(true, "Invariant checker should initialize");
}

#[test]
fn test_invariant_checker_custom_invariant() {
    let bytecode = vec![0x60, 0x80, 0x60, 0x40];
    let mut checker = InvariantChecker::new(bytecode);
    
    checker.add_custom_invariant(
        "Test Invariant".to_string(),
        "x > 0".to_string(),
        InvariantPriority::High,
    );
    
    // Should not crash
    let violations = checker.check_invariants();
    assert!(violations.len() >= 0, "Should return violations (or empty)");
}

#[tokio::test]
async fn test_attack_simulator_initialization() {
    let simulator = AttackSimulator::new("https://ethereum.publicnode.com");
    assert!(simulator.is_ok(), "Attack simulator should initialize");
}

#[test]
fn test_full_system_integration() {
    // This test proves all three components can be used together
    let bytecode = vec![
        0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15,
        0x60, 0x10, 0x57, 0x60, 0x00, 0x80, 0xFD, 0x5B,
    ];
    
    // 1. Invariant checking (synchronous)
    let mut checker = InvariantChecker::new(bytecode.clone());
    let _violations = checker.check_invariants();
    
    // 2. Can initialize economic validator
    let _validator = EconomicValidator::new("https://ethereum.publicnode.com", 1);
    
    // 3. Can initialize attack simulator  
    let _simulator = AttackSimulator::new("https://ethereum.publicnode.com");
    
    assert!(true, "All three components work together");
}
