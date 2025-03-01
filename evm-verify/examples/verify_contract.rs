// Example of verifying a contract using EVM Verify
//
// This example demonstrates how to verify a smart contract using
// the EVM Verify framework with Proof-Carrying Code (PCC).

use evm_verify::api::{EVMVerify, ReportFormatter, ReportFormat};
use evm_verify::UnifiedVerifier;
use ethers::types::Bytes;
use std::error::Error;
use hex;

fn main() -> Result<(), Box<dyn Error>> {
    println!("EVM Verify - Contract Verification Example");
    println!("===========================================\n");
    
    // Create a verifier
    let verifier = EVMVerify::new();
    
    // Sample bytecode for a simple contract that increments a counter
    let bytecode_hex = "608060405234801561001057600080fd5b5060b28061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80636d4ce63c146037578063d09de08a146053575b600080fd5b603d605b565b6040518082815260200191505060405180910390f35b6059606a565b005b60008054905090565b60016000540160008190555056fea2646970667358221220c7845a1e7cbde4c43ab6a25f6c0d6a1c6c3a9af3f0c2b4b8e220e7c25d66709c64736f6c63430007060033";
    let bytecode = Bytes::from(hex::decode(bytecode_hex)?);
    
    println!("Analyzing contract bytecode...");
    println!("Bytecode size: {} bytes\n", bytecode.len());
    
    // Analyze the bytecode
    let report = verifier.analyze_bytecode(bytecode.clone())?;
    
    // Print the report summary
    println!("Analysis completed at: {}", report.timestamp);
    println!("Found {} vulnerabilities\n", report.vulnerabilities.len());
    
    // Print vulnerabilities
    if !report.vulnerabilities.is_empty() {
        println!("Vulnerabilities:");
        println!("----------------");
        
        for (i, vuln) in report.vulnerabilities.iter().enumerate() {
            println!("\nVulnerability #{}", i + 1);
            println!("Title: {}", vuln.title);
            println!("Description: {}", vuln.description);
            println!("Severity: {:?}", vuln.severity);
            println!("Type: {:?}", vuln.vulnerability_type);
            println!("Recommendation: {}", vuln.recommendation);
        }
    } else {
        println!("No vulnerabilities found!");
    }
    
    // Generate a proof using the unified verifier
    println!("\nGenerating PCC proof...");
    let unified_verifier = UnifiedVerifier::new();
    
    match unified_verifier.generate_pcc_proof(&bytecode) {
        Ok(proof) => {
            println!("Proof generated successfully!");
            
            // Verify the proof
            println!("\nVerifying proof...");
            match unified_verifier.verify_pcc_proof(&bytecode, &proof) {
                Ok(valid) => {
                    if valid {
                        println!("Proof verification successful!");
                    } else {
                        println!("Proof verification failed!");
                    }
                },
                Err(e) => println!("Error verifying proof: {}", e),
            }
        },
        Err(e) => println!("Error generating proof: {}", e),
    }
    
    // Save the report to a file
    println!("\nSaving report to file...");
    match ReportFormatter::save_to_file(&report, "contract_report.json", ReportFormat::Json) {
        Ok(_) => println!("Report saved to contract_report.json"),
        Err(e) => println!("Error saving report: {}", e),
    }
    
    Ok(())
}
