// Example of verifying a state transition using EVM Verify
//
// This example demonstrates how to verify a state transition using
// the EVM Verify framework with Proof-Carrying Data (PCD).

use evm_verify::UnifiedVerifier;
use evm_verify::api::{Vulnerability, VulnerabilityType};
use ethers::types::{Bytes, Address, U256};
use std::error::Error;
use hex;
use std::str::FromStr;

fn main() -> Result<(), Box<dyn Error>> {
    println!("EVM Verify - State Transition Verification Example");
    println!("==================================================\n");
    
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // Sample bytecode for a simple token transfer
    let bytecode_hex = "608060405234801561001057600080fd5b506004361061004c576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a9059cbb14610051575b600080fd5b6100a76004803603810190808035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610109565b604051808215151515815260200191505060405180910390f35b60008273ffffffffffffffffffffffffffffffffffffffff16828460405180828152602001915050600060405180830381858888f19350505050905092915050565b";
    let bytecode = Bytes::from(hex::decode(bytecode_hex)?);
    
    println!("Analyzing contract bytecode...");
    println!("Bytecode size: {} bytes\n", bytecode.len());
    
    // Analyze the bytecode using the unified verifier
    let report = verifier.analyze_bytecode(bytecode.clone())?;
    
    println!("Analysis completed at: {}", report.timestamp);
    println!("Found {} vulnerabilities\n", report.vulnerabilities.len());
    
    // Filter for state transition related vulnerabilities
    let state_vulnerabilities: Vec<&Vulnerability> = report.vulnerabilities.iter()
        .filter(|v| matches!(v.vulnerability_type, 
                            VulnerabilityType::FlashLoan | 
                            VulnerabilityType::Reentrancy | 
                            VulnerabilityType::OracleManipulation))
        .collect();
    
    println!("Found {} state transition related vulnerabilities", state_vulnerabilities.len());
    
    // Print state transition vulnerabilities
    if !state_vulnerabilities.is_empty() {
        println!("\nState Transition Vulnerabilities:");
        println!("--------------------------------");
        
        for (i, vuln) in state_vulnerabilities.iter().enumerate() {
            println!("\nVulnerability #{}", i + 1);
            println!("Title: {}", vuln.title);
            println!("Description: {}", vuln.description);
            println!("Severity: {:?}", vuln.severity);
            println!("Type: {:?}", vuln.vulnerability_type);
            println!("Recommendation: {}", vuln.recommendation);
        }
    } else {
        println!("\nNo state transition vulnerabilities found!");
    }
    
    // Generate a proof
    println!("\nGenerating PCD proof...");
    match verifier.generate_pcd_proof(&bytecode) {
        Ok(proof) => {
            println!("Proof generated successfully!");
            
            // Verify the proof
            println!("\nVerifying proof...");
            match verifier.verify_pcd_proof(&bytecode, &proof) {
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
    
    println!("\n-----------------------------------\n");
    
    // Demonstrate a manual state transition verification
    println!("Manual State Transition Verification Example");
    println!("===========================================\n");
    
    // Create sample initial and final states for a token transfer
    let sender = Address::from_str("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")?;
    let recipient = Address::from_str("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")?;
    let amount = U256::from(100);
    
    // Initial state (before transfer)
    let initial_balance_sender = U256::from(1000);
    let initial_balance_recipient = U256::from(500);
    
    // Final state (after transfer)
    let final_balance_sender = initial_balance_sender.checked_sub(amount).unwrap();
    let final_balance_recipient = initial_balance_recipient.checked_add(amount).unwrap();
    
    println!("Token Transfer:");
    println!("Sender: {}", sender);
    println!("Recipient: {}", recipient);
    println!("Amount: {}", amount);
    println!("\nInitial State:");
    println!("Sender Balance: {}", initial_balance_sender);
    println!("Recipient Balance: {}", initial_balance_recipient);
    println!("\nFinal State:");
    println!("Sender Balance: {}", final_balance_sender);
    println!("Recipient Balance: {}", final_balance_recipient);
    
    // Verify the state transition (simplified example)
    let is_valid = final_balance_sender.checked_add(final_balance_recipient).unwrap() ==
                   initial_balance_sender.checked_add(initial_balance_recipient).unwrap();
    
    println!("\nState Transition Valid: {}", is_valid);
    
    Ok(())
}
