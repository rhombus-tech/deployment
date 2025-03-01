use evm_verify::UnifiedVerifier;
use ethers::types::Bytes;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // Simple bytecode example: PUSH1 1 PUSH1 0 SSTORE
    let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]);
    
    println!("Analyzing bytecode: 0x{}", hex::encode(&bytecode));
    
    // Analyze bytecode
    let report = verifier.analyze_bytecode(bytecode.clone())?;
    
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
    let pcc_report = pcc_verifier.analyze_bytecode(bytecode.clone())?;
    println!("Found {} vulnerabilities", pcc_report.vulnerabilities.len());
    
    println!("\n--- PCD Only Analysis ---");
    let pcd_verifier = UnifiedVerifier::with_config(true, false);
    let pcd_report = pcd_verifier.analyze_bytecode(bytecode.clone())?;
    println!("Found {} vulnerabilities", pcd_report.vulnerabilities.len());
    
    Ok(())
}
