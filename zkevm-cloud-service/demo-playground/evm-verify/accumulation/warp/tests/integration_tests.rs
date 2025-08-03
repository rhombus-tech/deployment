use evm_verify::accumulation::warp::integration::{
    is_warp_strategy, create_warp_context, create_warp_context_with_params,
    verify_with_warp, conversion, encoding
};
use evm_verify::accumulation::warp::verification::{
    SecurityReport, SecurityWarning, WarpVerificationStrategy
};
use evm_verify::api::VerificationStrategy;
use pcd::gateway::{SecurityReport as PCDSecurityReport, SecurityWarning as PCDSecurityWarning};
use pcd::circuit_impl::SecurityWarningKind;
use pcd::Severity;
use std::sync::Arc;

#[test]
fn test_is_warp_strategy() {
    // Test with different strategies
    let warp_strategy = unsafe { std::mem::transmute::<u8, VerificationStrategy>(99) };
    let groth16_strategy = VerificationStrategy::Groth16;
    
    assert!(is_warp_strategy(&warp_strategy));
    assert!(!is_warp_strategy(&groth16_strategy));
}

#[test]
fn test_create_warp_context() {
    // Create a context with default parameters
    let context = create_warp_context();
    
    // Should be valid and use default security parameter
    assert_eq!(context.security_param(), 128);
}

#[test]
fn test_create_warp_context_with_params() {
    // Create a context with custom security parameter
    let security_param = 256;
    let context = create_warp_context_with_params(security_param);
    
    // Should use the specified security parameter
    assert_eq!(context.security_param(), security_param);
}

#[tokio::test]
async fn test_verify_with_warp() {
    // Create a WARP context
    let context = create_warp_context();
    
    // Create a simple verification function
    let verification_fn = |ctx: Arc<WarpVerificationStrategy>, data: &[u8], level: u32| async move {
        // For testing, we'll just return a dummy success report
        Ok(SecurityReport {
            passed: true,
            warnings: vec![],
            verification_time_ms: 42,
        })
    };
    
    // Test data and security level
    let test_data = vec![1, 2, 3, 4, 5];
    let security_level = 2;
    
    // Call verify_with_warp
    let result = verify_with_warp(
        context,
        verification_fn,
        &test_data,
        security_level
    ).await;
    
    // Should succeed and return a properly converted report
    assert!(result.is_ok());
    let pcd_report = result.unwrap();
    assert!(pcd_report.passed);
    assert!(pcd_report.warnings.is_empty());
    
    // Should have metrics with WARP-specific fields
    assert!(pcd_report.metrics.is_some());
    let metrics = pcd_report.metrics.unwrap();
    assert!(metrics.get("warp_enabled").is_some());
    assert!(metrics.get("cryptographic_scheme").is_some());
    assert!(metrics.get("security_level").is_some());
}

#[test]
fn test_conversion_to_pcd_warnings() {
    // Create WARP security warnings
    let warp_warnings = vec![
        SecurityWarning::InvalidProof("Invalid KZG proof".to_string()),
        SecurityWarning::PotentialMEV("Potential frontrunning detected".to_string()),
        SecurityWarning::UnexpectedState("Unexpected accumulator state".to_string()),
        SecurityWarning::MalformedTransaction("Transaction missing required fields".to_string()),
    ];
    
    // Convert to PCD warnings
    let pcd_warnings = conversion::to_pcd_warnings(warp_warnings);
    
    // Check conversion
    assert_eq!(pcd_warnings.len(), 4);
    
    // Check first warning
    assert_eq!(pcd_warnings[0].kind, SecurityWarningKind::InvalidProof);
    assert_eq!(pcd_warnings[0].message, "Invalid KZG proof");
    assert_eq!(pcd_warnings[0].severity, Severity::Critical);
    
    // Check second warning
    assert_eq!(pcd_warnings[1].kind, SecurityWarningKind::PotentialMEV);
    assert_eq!(pcd_warnings[1].message, "Potential frontrunning detected");
    assert_eq!(pcd_warnings[1].severity, Severity::High);
}

#[test]
fn test_conversion_to_pcd_report() {
    // Create a WARP security report
    let warp_report = SecurityReport {
        passed: true,
        warnings: vec![
            SecurityWarning::InvalidProof("Test warning".to_string()),
        ],
        verification_time_ms: 123,
    };
    
    // Convert to PCD report
    let pcd_report = conversion::to_pcd_report(warp_report);
    
    // Check conversion
    assert!(pcd_report.passed);
    assert_eq!(pcd_report.warnings.len(), 1);
    assert_eq!(pcd_report.warnings[0].kind, SecurityWarningKind::InvalidProof);
    assert!(pcd_report.metrics.is_some());
    
    let metrics = pcd_report.metrics.unwrap();
    assert_eq!(metrics.get("verification_time_ms").unwrap().as_u64().unwrap(), 123);
    assert!(metrics.get("warp_enabled").is_some());
}

#[test]
fn test_conversion_from_pcd_report() {
    // Create a PCD security report
    let pcd_report = PCDSecurityReport {
        passed: true,
        warnings: vec![
            PCDSecurityWarning {
                kind: SecurityWarningKind::InvalidProof,
                message: "PCD test warning".to_string(),
                severity: Severity::Critical,
                location: None,
            },
        ],
        metrics: Some(serde_json::json!({
            "verification_time_ms": 456
        })),
    };
    
    // Convert to WARP report
    let warp_report = conversion::from_pcd_report(pcd_report);
    
    // Check conversion
    assert!(warp_report.passed);
    assert_eq!(warp_report.warnings.len(), 1);
    match &warp_report.warnings[0] {
        SecurityWarning::InvalidProof(msg) => assert_eq!(msg, "PCD test warning"),
        _ => panic!("Wrong warning type"),
    }
    assert_eq!(warp_report.verification_time_ms, 456);
}

#[test]
fn test_transaction_encoding() {
    // Create a small test transaction
    let small_tx = vec![1, 2, 3, 4, 5];
    
    // Encode the transaction
    let encoded = encoding::encode_transaction(&small_tx);
    
    // Should have one field element per byte for small transactions
    assert_eq!(encoded.len(), small_tx.len());
    
    // Create a large test transaction (> 1024 bytes)
    let large_tx = vec![42u8; 1025];
    
    // Encode the large transaction
    let encoded_large = encoding::encode_transaction(&large_tx);
    
    // Should use the more efficient encoding (approximately 1/8 the size)
    assert!(encoded_large.len() < large_tx.len());
    assert!(encoded_large.len() >= large_tx.len() / 8);
    
    // Test decoding
    let small_tx_decoded = encoding::decode_transaction(&encoded);
    
    // The decoded transaction might have padding bytes at the end
    assert!(small_tx_decoded.starts_with(&small_tx));
}
