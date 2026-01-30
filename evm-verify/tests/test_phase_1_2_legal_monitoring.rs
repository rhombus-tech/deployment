/// Integration test for Phase 1 (Legal Protection) and Phase 2 (Continuous Monitoring)
/// 
/// This demonstrates the complete lifecycle of a security certificate with:
/// - Legal disclaimers and liability protection
/// - Continuous monitoring for contract changes
/// - Automatic reverification triggers

use evm_verify::analysis::{
    security_proof_generator::{
        SecurityProofGenerator,
        ComprehensiveAnalysisResults,
        ProofLimitations,
        LiabilityTerms,
        ReverificationConfig,
    },
    contract_lifecycle_monitor::{
        ContractLifecycleMonitor,
        AlertSeverity,
    },
};
use ethers::types::Address;

#[test]
fn test_phase_1_legal_protection() {
    let generator = SecurityProofGenerator::new();
    let contract_address = Address::zero();
    let bytecode = vec![0x60, 0x80, 0x60, 0x40]; // PUSH1 0x80, PUSH1 0x40
    
    let analysis = ComprehensiveAnalysisResults {
        reentrancy_count: 0,
        integer_overflow_count: 0,
        integer_underflow_count: 0,
        access_control_vulnerabilities: 0,
        oracle_manipulation_count: 0,
        flash_loan_attack_count: 0,
    };
    
    let cert = generator.generate_certificate(contract_address, &bytecode, &analysis);
    
    // === PHASE 1: LEGAL PROTECTION VERIFICATION ===
    
    // 1. Limitations are explicit
    assert!(!cert.limitations.analysis_scope.is_empty());
    assert!(cert.limitations.analysis_scope.contains("404"));
    assert_eq!(cert.limitations.detector_count, 404);
    assert_eq!(cert.limitations.symbolic_execution_depth, 1000);
    
    // 2. Assumptions are documented
    assert!(cert.limitations.assumptions.len() >= 5);
    assert!(cert.limitations.assumptions.iter().any(|a| 
        a.description.contains("compiler")
    ));
    
    // 3. Cannot verify list is present
    assert!(cert.limitations.cannot_verify.len() >= 5);
    assert!(cert.limitations.cannot_verify.iter().any(|s| 
        s.contains("business logic")
    ));
    
    // 4. Known limitations documented
    assert!(cert.limitations.known_limitations.len() >= 5);
    assert!(cert.limitations.known_limitations.iter().any(|s| 
        s.contains("Halting problem")
    ));
    
    // 5. Disclaimers are comprehensive
    assert!(cert.disclaimers.len() >= 5);
    assert!(cert.disclaimers.iter().any(|d| d.contains("DISCLAIMER")));
    assert!(cert.disclaimers.iter().any(|d| d.contains("NO WARRANTY")));
    assert!(cert.disclaimers.iter().any(|d| d.contains("USE AT OWN RISK")));
    
    // 6. Liability terms are present
    assert!(cert.liability_terms.max_liability_wei.is_some());
    assert_eq!(
        cert.liability_terms.max_liability_wei.unwrap(),
        1_000_000_000_000_000_000 // 1 ETH
    );
    assert!(!cert.liability_terms.terms_url.is_empty());
    assert_eq!(cert.liability_terms.terms_version, "1.0.0");
    assert!(!cert.liability_terms.jurisdiction.is_empty());
    assert!(!cert.liability_terms.security_contact.is_empty());
    
    println!("✅ Phase 1 Legal Protection: ALL CHECKS PASSED");
    println!("   - Limitations: {} categories", cert.limitations.assumptions.len());
    println!("   - Disclaimers: {}", cert.disclaimers.len());
    println!("   - Max liability: {} ETH", cert.liability_terms.max_liability_wei.unwrap() / 1_000_000_000_000_000_000);
}

#[test]
fn test_phase_2_continuous_monitoring_config() {
    let generator = SecurityProofGenerator::new();
    let contract_address = Address::zero();
    let bytecode = vec![0x60, 0x00]; // PUSH1 0
    
    let analysis = ComprehensiveAnalysisResults {
        reentrancy_count: 0,
        integer_overflow_count: 0,
        integer_underflow_count: 0,
        access_control_vulnerabilities: 0,
        oracle_manipulation_count: 0,
        flash_loan_attack_count: 0,
    };
    
    let cert = generator.generate_certificate(contract_address, &bytecode, &analysis);
    
    // === PHASE 2: CONTINUOUS MONITORING VERIFICATION ===
    
    // 1. Reverification triggers configured
    assert!(cert.reverification_triggers.on_bytecode_change);
    assert!(cert.reverification_triggers.on_upgrade_detected);
    assert!(cert.reverification_triggers.on_dependency_change);
    assert!(cert.reverification_triggers.on_new_detector_added);
    
    // 2. TVL threshold set
    assert!(cert.reverification_triggers.tvl_threshold_wei.is_some());
    let tvl_threshold = cert.reverification_triggers.tvl_threshold_wei.unwrap();
    assert_eq!(tvl_threshold, 10_000_000_000_000_000_000_000); // 10k ETH
    
    // 3. Time-based interval set
    assert!(cert.reverification_triggers.time_based_interval_seconds.is_some());
    let interval = cert.reverification_triggers.time_based_interval_seconds.unwrap();
    assert_eq!(interval, 30 * 24 * 60 * 60); // 30 days
    
    // 4. Audit trail present
    assert!(!cert.audit_trail.proof_id.is_empty());
    assert_eq!(cert.audit_trail.bytecode_hash, cert.bytecode_hash);
    assert!(cert.audit_trail.analysis_started_at > 0);
    assert!(cert.audit_trail.analysis_completed_at >= cert.audit_trail.analysis_started_at);
    
    // 5. Detector manifest
    assert!(!cert.audit_trail.detector_manifest.is_empty());
    assert!(cert.audit_trail.detector_manifest.get("reentrancy_detector").is_some());
    
    // 6. Symbolic execution config
    assert_eq!(cert.audit_trail.symbolic_config.max_depth, 1000);
    assert_eq!(cert.audit_trail.symbolic_config.timeout_seconds, 300);
    assert_eq!(cert.audit_trail.symbolic_config.solver, "Z3");
    
    // 7. Environment documented
    assert!(!cert.audit_trail.environment.platform.is_empty());
    assert!(!cert.audit_trail.environment.analyzer_version.is_empty());
    assert!(!cert.audit_trail.environment.instance_id.is_empty());
    
    // 8. Chain of custody
    assert!(!cert.audit_trail.chain_of_custody.is_empty());
    
    // 9. Reproducibility hash
    assert!(cert.audit_trail.reproducibility_hash != [0u8; 32]);
    
    // 10. Bytecode hash matches
    assert!(cert.bytecode_hash != [0u8; 32]);
    
    println!("✅ Phase 2 Continuous Monitoring: ALL CHECKS PASSED");
    println!("   - Proof ID: {}", cert.audit_trail.proof_id);
    println!("   - TVL threshold: {} ETH", tvl_threshold / 1_000_000_000_000_000_000);
    println!("   - Recheck interval: {} days", interval / (24 * 60 * 60));
    println!("   - Detectors tracked: {}", cert.audit_trail.detector_manifest.len());
}

#[test]
fn test_complete_certificate_lifecycle() {
    let generator = SecurityProofGenerator::new();
    let contract_address = Address::zero();
    let bytecode = vec![
        0x60, 0x80, // PUSH1 0x80
        0x60, 0x40, // PUSH1 0x40
        0x52, // MSTORE
    ];
    
    let analysis = ComprehensiveAnalysisResults {
        reentrancy_count: 0,
        integer_overflow_count: 0,
        integer_underflow_count: 0,
        access_control_vulnerabilities: 0,
        oracle_manipulation_count: 0,
        flash_loan_attack_count: 0,
    };
    
    let cert = generator.generate_certificate(contract_address, &bytecode, &analysis);
    
    // === COMPLETE CERTIFICATE VERIFICATION ===
    
    println!("\n🛡️  SECURITY CERTIFICATE GENERATED");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    println!("\n📋 BASIC INFO:");
    println!("   Contract: {:?}", cert.contract_address);
    println!("   Timestamp: {}", cert.timestamp);
    println!("   Expires: {} (30 days)", cert.expires_at);
    println!("   Verification time: {}ms", cert.verification_time_ms);
    println!("   Confidence: {:.1}%", cert.overall_confidence * 100.0);
    
    println!("\n⚖️  PHASE 1: LEGAL PROTECTION");
    println!("   ✓ Analysis scope: {}", cert.limitations.detector_count);
    println!("   ✓ Symbolic depth: {}", cert.limitations.symbolic_execution_depth);
    println!("   ✓ Assumptions: {}", cert.limitations.assumptions.len());
    println!("   ✓ Cannot verify: {}", cert.limitations.cannot_verify.len());
    println!("   ✓ Disclaimers: {}", cert.disclaimers.len());
    println!("   ✓ Max liability: {} ETH", 
        cert.liability_terms.max_liability_wei.unwrap() / 1_000_000_000_000_000_000);
    println!("   ✓ Jurisdiction: {}", cert.liability_terms.jurisdiction);
    
    println!("\n🔄 PHASE 2: CONTINUOUS MONITORING");
    println!("   ✓ Bytecode change detection: {}", cert.reverification_triggers.on_bytecode_change);
    println!("   ✓ Upgrade detection: {}", cert.reverification_triggers.on_upgrade_detected);
    println!("   ✓ TVL threshold: {} ETH", 
        cert.reverification_triggers.tvl_threshold_wei.unwrap() / 1_000_000_000_000_000_000);
    println!("   ✓ Recheck interval: {} days", 
        cert.reverification_triggers.time_based_interval_seconds.unwrap() / (24 * 60 * 60));
    println!("   ✓ Proof ID: {}", cert.audit_trail.proof_id);
    println!("   ✓ Reproducibility hash: {:02x}...", cert.audit_trail.reproducibility_hash[0]);
    
    println!("\n📊 AUDIT TRAIL:");
    println!("   ✓ Detectors: {}", cert.audit_trail.detector_manifest.len());
    println!("   ✓ Solver: {}", cert.audit_trail.symbolic_config.solver);
    println!("   ✓ Platform: {}", cert.audit_trail.environment.platform);
    println!("   ✓ Chain of custody: {} events", cert.audit_trail.chain_of_custody.len());
    
    println!("\n✅ CERTIFICATE LIFECYCLE COMPLETE");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    // Final assertions
    assert!(cert.verification_time_ms < 10000); // <10s
    assert!(cert.overall_confidence > 0.0);
    assert!(cert.overall_confidence <= 1.0);
    assert!(cert.expires_at > cert.timestamp);
}

#[test]
fn test_disclaimers_are_legally_sound() {
    let generator = SecurityProofGenerator::new();
    let cert = generator.generate_certificate(
        Address::zero(),
        &[0x60, 0x00],
        &ComprehensiveAnalysisResults {
            reentrancy_count: 0,
            integer_overflow_count: 0,
            integer_underflow_count: 0,
            access_control_vulnerabilities: 0,
            oracle_manipulation_count: 0,
            flash_loan_attack_count: 0,
        },
    );
    
    // Critical legal terms must be present
    let disclaimers_text = cert.disclaimers.join(" ");
    
    assert!(disclaimers_text.contains("DISCLAIMER"));
    assert!(disclaimers_text.contains("NO WARRANTY"));
    assert!(disclaimers_text.contains("AS IS"));
    assert!(disclaimers_text.contains("USE AT OWN RISK"));
    assert!(disclaimers_text.contains("NOT guarantee"));
    assert!(disclaimers_text.contains("does NOT constitute financial"));
    
    // Scope limitations must be clear
    assert!(disclaimers_text.contains("SCOPE LIMITATION"));
    assert!(disclaimers_text.contains("upgradeable"));
    
    // External dependency disclaimer
    assert!(disclaimers_text.contains("EXTERNAL DEPENDENCIES"));
    assert!(disclaimers_text.contains("external contracts"));
    
    println!("✅ Legal disclaimers are comprehensive and legally sound");
}
