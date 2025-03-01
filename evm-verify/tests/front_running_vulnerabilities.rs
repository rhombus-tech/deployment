use evm_verify::api::{EVMVerify, ConfigManager};
use ethers::types::Bytes;
use hex_literal::hex;

#[test]
fn test_gas_price_dependency() {
    // Create bytecode with gas price dependency
    let bytecode = Bytes::from(hex!(
        "3A"   // GASPRICE
        "6001" // PUSH1 1
        "10"   // LT - compare gas price with 1
    ));
    
    // Create verifier with front-running detection enabled
    let config = ConfigManager::builder()
        .detect_front_running(true)
        .build();
    let verifier = EVMVerify::with_config(config);
    
    // Analyze bytecode
    let vulnerabilities = verifier.analyze_front_running_vulnerabilities(bytecode).unwrap();
    
    // Should detect gas price dependency
    assert!(!vulnerabilities.is_empty());
    assert_eq!(format!("{:?}", vulnerabilities[0].kind), "FrontRunning");
    assert!(vulnerabilities[0].description.contains("Gas price"));
}

#[test]
fn test_block_info_dependency() {
    // Create bytecode with block.timestamp dependency
    let bytecode = Bytes::from(hex!(
        "42"   // TIMESTAMP
        "6001" // PUSH1 1
        "10"   // LT - compare timestamp with 1
    ));
    
    // Create verifier with front-running detection enabled
    let config = ConfigManager::builder()
        .detect_front_running(true)
        .build();
    let verifier = EVMVerify::with_config(config);
    
    // Analyze bytecode
    let vulnerabilities = verifier.analyze_front_running_vulnerabilities(bytecode).unwrap();
    
    // Should detect block info dependency
    assert!(!vulnerabilities.is_empty());
    assert!(vulnerabilities[0].description.contains("Block information"));
}

#[test]
fn test_price_sensitive_operations() {
    // Create bytecode with price-sensitive operation
    let bytecode = Bytes::from(hex!(
        "6001" // PUSH1 1 - gas
        "6000" // PUSH1 0 - to
        "6000" // PUSH1 0 - value
        "6000" // PUSH1 0 - data offset
        "6000" // PUSH1 0 - data length
        "6000" // PUSH1 0 - out offset
        "6000" // PUSH1 0 - out length
        "F1"   // CALL - external call
        "6001" // PUSH1 1
        "6000" // PUSH1 0
        "55"   // SSTORE - store without checks
    ));
    
    // Create verifier with front-running detection enabled
    let config = ConfigManager::builder()
        .detect_front_running(true)
        .build();
    let verifier = EVMVerify::with_config(config);
    
    // Analyze bytecode
    let vulnerabilities = verifier.analyze_front_running_vulnerabilities(bytecode).unwrap();
    
    // Print the actual description for debugging
    if !vulnerabilities.is_empty() {
        println!("Actual description: {}", vulnerabilities[0].description);
    }
    
    // Should detect price-sensitive operation
    assert!(!vulnerabilities.is_empty());
    // Check for either "Price-sensitive operation" or "slippage protection" in the description
    assert!(vulnerabilities[0].description.contains("slippage protection") || 
            vulnerabilities[0].description.contains("Price-sensitive"));
}

#[test]
fn test_missing_slippage_protection() {
    // Create bytecode with missing slippage protection
    let bytecode = Bytes::from(hex!(
        "6001" // PUSH1 1 - gas
        "6000" // PUSH1 0 - to
        "6000" // PUSH1 0 - value
        "6000" // PUSH1 0 - data offset
        "6000" // PUSH1 0 - data length
        "6000" // PUSH1 0 - out offset
        "6000" // PUSH1 0 - out length
        "F1"   // CALL - external call without prior comparison
    ));
    
    // Create verifier with front-running detection enabled
    let config = ConfigManager::builder()
        .detect_front_running(true)
        .build();
    let verifier = EVMVerify::with_config(config);
    
    // Analyze bytecode
    let vulnerabilities = verifier.analyze_front_running_vulnerabilities(bytecode).unwrap();
    
    // Should detect missing slippage protection
    assert!(!vulnerabilities.is_empty());
    assert!(vulnerabilities[0].description.contains("slippage protection"));
}

#[test]
fn test_safe_code() {
    // Create bytecode without front-running vulnerabilities
    let bytecode = Bytes::from(hex!(
        "6001" // PUSH1 1
        "6000" // PUSH1 0
        "55"   // SSTORE - simple storage without price dependency
    ));
    
    // Create verifier with front-running detection enabled
    let config = ConfigManager::builder()
        .detect_front_running(true)
        .build();
    let verifier = EVMVerify::with_config(config);
    
    // Analyze bytecode
    let vulnerabilities = verifier.analyze_front_running_vulnerabilities(bytecode).unwrap();
    
    // Should not detect any front-running vulnerabilities
    assert!(vulnerabilities.is_empty());
}

#[test]
fn test_front_running_in_comprehensive_analysis() {
    // Create bytecode with gas price dependency
    let bytecode = Bytes::from(hex!(
        "3A"   // GASPRICE
        "6001" // PUSH1 1
        "10"   // LT - compare gas price with 1
        "6000" // PUSH1 0
        "57"   // JUMPI - conditional jump based on gas price
    ));
    
    // Create verifier with front-running detection enabled
    let config = ConfigManager::builder()
        .detect_front_running(true)
        .build();
    let verifier = EVMVerify::with_config(config);
    
    // Perform comprehensive analysis
    let report = verifier.analyze_bytecode(bytecode).unwrap();
    
    // Should detect front-running vulnerability
    let has_front_running = report.vulnerabilities.iter().any(|v| 
        v.description.contains("Gas price") || 
        v.description.contains("front-running")
    );
    
    assert!(has_front_running);
}
