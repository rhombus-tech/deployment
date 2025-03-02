use evm_verify::UnifiedVerifier;
use std::error::Error;
use ethers::types::Bytes;

fn main() -> Result<(), Box<dyn Error>> {
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // Example bytecode with access control vulnerability: PUSH1 1 PUSH1 0 SSTORE
    // This bytecode simply stores a value without any access control checks
    let vulnerable_bytecode: Vec<u8> = vec![0x60, 0x01, 0x60, 0x00, 0x55];
    let vulnerable_bytes = Bytes::from(vulnerable_bytecode);
    
    println!("Analyzing vulnerable bytecode: 0x{:x?}", vulnerable_bytes);
    
    // Generate PCC proof for vulnerable bytecode
    println!("\nGenerating PCC proof for vulnerable bytecode...");
    let vulnerable_proof = verifier.generate_pcc_proof(vulnerable_bytes.as_ref())?;
    println!("PCC proof generated successfully, size: {} bytes", vulnerable_proof.len());
    
    // Verify PCC proof for vulnerable bytecode
    println!("\nVerifying PCC proof for vulnerable bytecode...");
    let vulnerable_result = verifier.verify_pcc_proof(vulnerable_bytes.as_ref(), vulnerable_proof.as_ref())?;
    println!("Verification result: is_valid = {}", vulnerable_result.is_valid);
    
    // Print detected vulnerabilities
    println!("\nDetected vulnerabilities:");
    if vulnerable_result.vulnerabilities.is_empty() {
        println!("No vulnerabilities detected (unexpected)");
    } else {
        for (i, vuln) in vulnerable_result.vulnerabilities.iter().enumerate() {
            println!("{}. {}", i + 1, vuln);
        }
    }
    
    // Example bytecode with access control check (simplified)
    // This bytecode includes a basic check before SSTORE
    // CALLER (get msg.sender)
    // PUSH20 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (hardcoded address)
    // EQ (check if caller equals the address)
    // PUSH1 0x0c (address to jump if check fails)
    // JUMPI (conditional jump)
    // PUSH1 0x01 (value to store)
    // PUSH1 0x00 (storage slot)
    // SSTORE (store the value)
    // JUMPDEST (destination for the jump)
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
    
    println!("\n\nAnalyzing protected bytecode: 0x{:x?}", protected_bytes);
    
    // Generate PCC proof for protected bytecode
    println!("\nGenerating PCC proof for protected bytecode...");
    let protected_proof = verifier.generate_pcc_proof(protected_bytes.as_ref())?;
    println!("PCC proof generated successfully, size: {} bytes", protected_proof.len());
    
    // Verify PCC proof for protected bytecode
    println!("\nVerifying PCC proof for protected bytecode...");
    let protected_result = verifier.verify_pcc_proof(protected_bytes.as_ref(), protected_proof.as_ref())?;
    println!("Verification result: is_valid = {}", protected_result.is_valid);
    
    // Print detected vulnerabilities
    println!("\nDetected vulnerabilities:");
    if protected_result.vulnerabilities.is_empty() {
        println!("No vulnerabilities detected (expected for protected bytecode)");
    } else {
        for (i, vuln) in protected_result.vulnerabilities.iter().enumerate() {
            println!("{}. {}", i + 1, vuln);
        }
    }
    
    // Example bytecode with weak access control (hardcoded address)
    // This might still be detected as a vulnerability due to using a hardcoded address
    println!("\n\nComparing the two results:");
    println!("Vulnerable bytecode: {} vulnerabilities", vulnerable_result.vulnerabilities.len());
    println!("Protected bytecode: {} vulnerabilities", protected_result.vulnerabilities.len());
    
    Ok(())
}
