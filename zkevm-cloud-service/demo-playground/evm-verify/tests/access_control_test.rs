use evm_verify::UnifiedVerifier;
use ethers::types::Bytes;

#[test]
fn test_access_control_vulnerability_detection() {
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // Bytecode with access control vulnerability: PUSH1 1 PUSH1 0 SSTORE
    // This bytecode simply stores a value without any access control checks
    let vulnerable_bytecode: Vec<u8> = vec![0x60, 0x01, 0x60, 0x00, 0x55];
    let vulnerable_bytes = Bytes::from(vulnerable_bytecode);
    
    // Generate and verify PCC proof for vulnerable bytecode
    let vulnerable_proof = verifier.generate_pcc_proof(vulnerable_bytes.as_ref()).unwrap();
    let vulnerable_result = verifier.verify_pcc_proof(vulnerable_bytes.as_ref(), vulnerable_proof.as_ref()).unwrap();
    
    // Verify that the proof is valid
    assert!(vulnerable_result.is_valid, "Proof should be valid");
    
    // Verify that access control vulnerabilities are detected
    assert!(!vulnerable_result.vulnerabilities.is_empty(), "Should detect access control vulnerabilities");
    
    // Check if any of the vulnerabilities mention "access control"
    let has_access_control_vuln = vulnerable_result.vulnerabilities.iter()
        .any(|v| v.to_lowercase().contains("access control"));
    
    assert!(has_access_control_vuln, "Should detect access control vulnerabilities specifically");
    
    // Bytecode with access control check (simplified)
    let protected_bytecode: Vec<u8> = vec![
        0x33, // CALLER
        0x73, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // PUSH20 address
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0x14, // EQ
        0x60, 0x0c, // PUSH1 0x0c (jump destination)
        0x57, // JUMPI
        0x60, 0x01, // PUSH1 0x01 (value)
        0x60, 0x00, // PUSH1 0x00 (slot)
        0x55, // SSTORE
        0x5b  // JUMPDEST
    ];
    let protected_bytes = Bytes::from(protected_bytecode);
    
    // Generate and verify PCC proof for protected bytecode
    let protected_proof = verifier.generate_pcc_proof(protected_bytes.as_ref()).unwrap();
    let protected_result = verifier.verify_pcc_proof(protected_bytes.as_ref(), protected_proof.as_ref()).unwrap();
    
    // Verify that the proof is valid
    assert!(protected_result.is_valid, "Protected bytecode proof should be valid");
    
    // The protected bytecode might still have vulnerabilities (like hardcoded address),
    // but it should have fewer than the completely unprotected bytecode
    assert!(protected_result.vulnerabilities.len() <= vulnerable_result.vulnerabilities.len(),
            "Protected bytecode should have fewer or equal vulnerabilities");
}

#[test]
fn test_proof_tampering_detection() {
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // Bytecode with access control vulnerability: PUSH1 1 PUSH1 0 SSTORE
    let bytecode: Vec<u8> = vec![0x60, 0x01, 0x60, 0x00, 0x55];
    let bytecode_bytes = Bytes::from(bytecode);
    
    // Generate PCC proof
    let mut proof = verifier.generate_pcc_proof(bytecode_bytes.as_ref()).unwrap();
    
    // Tamper with the proof by modifying a byte in the bytecode section
    if proof.len() > 3 {
        proof[2] = proof[2].wrapping_add(1);
    }
    
    // Verify the tampered proof
    let result = verifier.verify_pcc_proof(bytecode_bytes.as_ref(), proof.as_ref()).unwrap();
    
    // The verification should fail because the proof has been tampered with
    assert!(!result.is_valid, "Tampered proof should be invalid");
}

#[test]
fn test_proof_format_compatibility() {
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // Bytecode with access control vulnerability: PUSH1 1 PUSH1 0 SSTORE
    let bytecode = vec![0x60, 0x01, 0x60, 0x00, 0x55];
    let bytecode_len = bytecode.len();
    let bytecode_bytes = Bytes::from(bytecode);
    
    // Generate PCC proof
    let proof = verifier.generate_pcc_proof(bytecode_bytes.as_ref()).unwrap();
    
    // Verify that the proof contains vulnerability information
    assert!(proof.len() > bytecode_len + 32, "Proof should contain vulnerability information");
    
    // Verify the proof
    let result = verifier.verify_pcc_proof(bytecode_bytes.as_ref(), proof.as_ref()).unwrap();
    
    // The verification should succeed
    assert!(result.is_valid, "Proof should be valid");
    
    // Verify that vulnerabilities are extracted from the proof
    assert!(!result.vulnerabilities.is_empty(), "Should extract vulnerabilities from proof");
}
