use evm_verify::UnifiedVerifier;
use ethers::types::Bytes;
use std::error::Error;
use hex;

fn main() -> Result<(), Box<dyn Error>> {
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // This is a simplified ERC20 token contract bytecode
    // It contains the basic functions: transfer, balanceOf, totalSupply
    let bytecode_hex = "60806040526004361061004c576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806318160ddd1461005157806370a0823114610079575b600080fd5b34801561005d57600080fd5b506100666100d0565b6040518082815260200191505060405180910390f35b34801561008557600080fd5b506100ba600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506100d6565b6040518082815260200191505060405180910390f35b60005481565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b";
    let bytecode = Bytes::from(hex::decode(bytecode_hex)?);
    
    println!("Analyzing ERC20 token contract bytecode");
    println!("Bytecode size: {} bytes", bytecode.len());
    
    // Analyze bytecode
    let report = verifier.analyze_bytecode(bytecode)?;
    
    // Print the report
    println!("\nAnalysis Report:");
    println!("Timestamp: {}", report.timestamp);
    println!("Contract size: {} bytes", report.contract_size);
    println!("Found {} vulnerabilities", report.vulnerabilities.len());
    
    // Print vulnerabilities
    if !report.vulnerabilities.is_empty() {
        println!("\nVulnerabilities:");
        for (i, vuln) in report.vulnerabilities.iter().enumerate() {
            println!("\nVulnerability #{}", i + 1);
            println!("Title: {}", vuln.title);
            println!("Description: {}", vuln.description);
            println!("Severity: {:?}", vuln.severity);
            println!("Type: {:?}", vuln.vulnerability_type);
            println!("Recommendation: {}", vuln.recommendation);
        }
    } else {
        println!("\nNo vulnerabilities found!");
    }
    
    // Print additional metrics
    println!("\nAdditional Metrics:");
    println!("Delegate calls: {}", report.delegate_calls);
    println!("Memory accesses: {}", report.memory_accesses);
    println!("Storage accesses: {}", report.storage_accesses);
    
    // Print analysis configuration
    println!("\nAnalysis Configuration:");
    println!("Test mode: {}", report.analysis_config.test_mode);
    println!("Max depth: {}", report.analysis_config.max_depth);
    
    Ok(())
}
