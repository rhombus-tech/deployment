use evm_verify::UnifiedVerifier;
use std::error::Error;
use ethers::types::Bytes;

fn main() -> Result<(), Box<dyn Error>> {
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // Simple bytecode example: PUSH1 1 PUSH1 0 SSTORE
    let bytecode_vec: Vec<u8> = vec![0x60, 0x01, 0x60, 0x00, 0x55];
    let bytecode_bytes = Bytes::from(bytecode_vec);
    
    println!("Analyzing bytecode: 0x{:x?}", bytecode_bytes);
    
    // Analyze bytecode - this method takes &[u8]
    let report = verifier.analyze_bytecode(bytecode_bytes.as_ref())?;
    
    // Print the report
    println!("Analysis completed at: {}", report.timestamp);
    println!("Contract size: {} bytes", report.contract_size);
    println!("Found {} vulnerabilities", report.vulnerabilities.len());
    
    // Print vulnerabilities
    for (i, vuln) in report.vulnerabilities.iter().enumerate() {
        println!("\nVulnerability #{}", i + 1);
        println!("Title: {}", vuln.title);
        println!("Description: {}", vuln.description);
        println!("Severity: {:?}", vuln.severity);
        println!("Type: {:?}", vuln.vulnerability_type);
        println!("Recommendation: {}", vuln.recommendation);
    }
    
    // Try with different configurations
    println!("\n--- PCC Only Analysis ---");
    let pcc_verifier = UnifiedVerifier::with_config(false, true);
    let pcc_report = pcc_verifier.analyze_bytecode(bytecode_bytes.as_ref())?;
    println!("Found {} vulnerabilities", pcc_report.vulnerabilities.len());
    
    println!("\n--- PCD Only Analysis ---");
    let pcd_verifier = UnifiedVerifier::with_config(true, false);
    let pcd_report = pcd_verifier.analyze_bytecode(bytecode_bytes.as_ref())?;
    println!("Found {} vulnerabilities", pcd_report.vulnerabilities.len());
    
    // Demonstrate proof generation and verification
    println!("\n--- Proof Generation and Verification ---");
    
    // Generate PCC proof - these methods take &[u8]
    println!("\nGenerating PCC proof...");
    let pcc_proof = verifier.generate_pcc_proof(bytecode_bytes.as_ref())?;
    println!("PCC proof generated successfully");
    
    // Verify PCC proof - these methods take &[u8]
    println!("\nVerifying PCC proof...");
    let pcc_verification_result = verifier.verify_pcc_proof(bytecode_bytes.as_ref(), pcc_proof.as_ref())?;
    println!("PCC proof verification result: {:?}", pcc_verification_result);
    
    // Generate PCD proof - these methods take &[u8]
    println!("\nGenerating PCD proof...");
    let (pcd_proof, pcd_verifying_key) = verifier.generate_pcd_proof(bytecode_bytes.as_ref())?;
    println!("PCD proof generated successfully");
    
    // Verify PCD proof - these methods take &[u8]
    println!("\nVerifying PCD proof...");
    let pcd_verification_result = verifier.verify_pcd_proof(bytecode_bytes.as_ref(), pcd_proof.as_ref(), pcd_verifying_key.as_ref())?;
    println!("PCD proof verification result: {:?}", pcd_verification_result);
    
    // Example with a more complex bytecode (this is still a simple example)
    println!("\n--- Testing with more complex bytecode ---");
    // This bytecode includes a simple loop pattern
    let complex_bytecode_vec: Vec<u8> = vec![
        0x60, 0x0A, // PUSH1 10 (counter)
        0x60, 0x00, // PUSH1 0 (index)
        0x5B,       // JUMPDEST (loop start)
        0x81,       // DUP2
        0x11,       // GT
        0x60, 0x09, // PUSH1 9 (exit address)
        0x57,       // JUMPI (conditional jump to exit)
        0x60, 0x01, // PUSH1 1
        0x01,       // ADD (increment index)
        0x60, 0x02, // PUSH1 2
        0x56,       // JUMP (jump back to loop start)
        0x5B,       // JUMPDEST (exit)
        0x00        // STOP
    ];
    let complex_bytecode_bytes = Bytes::from(complex_bytecode_vec);
    
    println!("Complex bytecode: 0x{:x?}", complex_bytecode_bytes);
    
    // Generate and verify PCC proof for complex bytecode
    println!("\nGenerating and verifying PCC proof for complex bytecode...");
    let complex_pcc_proof = verifier.generate_pcc_proof(complex_bytecode_bytes.as_ref())?;
    let complex_pcc_result = verifier.verify_pcc_proof(complex_bytecode_bytes.as_ref(), complex_pcc_proof.as_ref())?;
    println!("Complex bytecode PCC verification result: {:?}", complex_pcc_result);
    
    // Generate and verify PCD proof for complex bytecode
    println!("\nGenerating and verifying PCD proof for complex bytecode...");
    let (complex_pcd_proof, complex_pcd_verifying_key) = verifier.generate_pcd_proof(complex_bytecode_bytes.as_ref())?;
    let complex_pcd_result = verifier.verify_pcd_proof(complex_bytecode_bytes.as_ref(), complex_pcd_proof.as_ref(), complex_pcd_verifying_key.as_ref())?;
    println!("Complex bytecode PCD verification result: {:?}", complex_pcd_result);
    
    Ok(())
}
