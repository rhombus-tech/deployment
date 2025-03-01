use evm_verify::UnifiedVerifier;
use ethers::types::Bytes;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // Example bytecode (simple storage contract)
    let bytecode = Bytes::from(vec![
        // PUSH1 0x80 PUSH1 0x40 MSTORE (constructor)
        0x60, 0x80, 0x60, 0x40, 0x52,
        // CALLVALUE DUP1 ISZERO PUSH2 0x0010 JUMPI
        0x34, 0x80, 0x15, 0x61, 0x00, 0x10, 0x57,
        // PUSH1 0x00 DUP1 REVERT
        0x60, 0x00, 0x80, 0xFD,
        // JUMPDEST POP (constructor end)
        0x5B, 0x50,
        // PUSH1 0x01 PUSH1 0x00 SSTORE (store 1 at storage slot 0)
        0x60, 0x01, 0x60, 0x00, 0x55
    ]);
    
    println!("Analyzing bytecode with length: {} bytes", bytecode.len());
    
    // Step 1: Analyze bytecode
    println!("\n=== Step 1: Basic Analysis ===");
    let report = verifier.analyze_bytecode(bytecode.clone())?;
    println!("Analysis completed at: {}", report.timestamp);
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
    
    // Step 2: Generate and verify PCC proof (with error handling)
    println!("\n=== Step 2: Generate PCC Proof ===");
    match verifier.generate_pcc_proof(&bytecode) {
        Ok(pcc_proof) => {
            println!("PCC Proof generated successfully");
            println!("Proof generated with bytecode of size: {} bytes", bytecode.len());
            
            // Step 3: Verify PCC proof
            println!("\n=== Step 3: Verify PCC Proof ===");
            match verifier.verify_pcc_proof(&bytecode, &pcc_proof) {
                Ok(result) => println!("PCC Proof verification result: {}", result),
                Err(e) => println!("PCC Proof verification error: {}", e),
            }
        },
        Err(e) => println!("PCC Proof generation error: {}", e),
    }
    
    // Step 4: Generate and verify PCD proof (with error handling)
    println!("\n=== Step 4: Generate PCD Proof ===");
    match verifier.generate_pcd_proof(&bytecode) {
        Ok(pcd_proof) => {
            println!("PCD Proof generated successfully");
            println!("Proof generated with bytecode of size: {} bytes", bytecode.len());
            
            // Step 5: Verify PCD proof
            println!("\n=== Step 5: Verify PCD Proof ===");
            match verifier.verify_pcd_proof(&bytecode, &pcd_proof) {
                Ok(result) => println!("PCD Proof verification result: {}", result),
                Err(e) => println!("PCD Proof verification error: {}", e),
            }
        },
        Err(e) => println!("PCD Proof generation error: {}", e),
    }
    
    // Step 6: Analyze with combined methods
    println!("\n=== Step 6: Combined Analysis ===");
    
    // Create verifiers with different configurations
    println!("PCC-only analysis:");
    let pcc_verifier = UnifiedVerifier::with_config(false, true);
    let pcc_report = pcc_verifier.analyze_bytecode(bytecode.clone())?;
    println!("PCC-only analysis found {} vulnerabilities", pcc_report.vulnerabilities.len());
    
    println!("\nPCD-only analysis:");
    let pcd_verifier = UnifiedVerifier::with_config(true, false);
    let pcd_report = pcd_verifier.analyze_bytecode(bytecode.clone())?;
    println!("PCD-only analysis found {} vulnerabilities", pcd_report.vulnerabilities.len());
    
    Ok(())
}
