use evm_verify::api::{EVMVerify, ConfigManager};
use ethers::types::Bytes;
use hex;
use anyhow::Result;

fn main() -> Result<()> {
    println!("EVM-Verify Precision Vulnerability Detection Example");
    println!("===================================================\n");

    // For this example, we'll use pre-compiled bytecode
    // In a real application, you would compile the Solidity code or load bytecode from a file
    println!("Using pre-compiled bytecode for PrecisionVulnerable contract");
    
    // This is a simplified bytecode representation for demonstration purposes
    // In a real scenario, you would get this from the compiled contract
    let bytecode_hex = "608060405234801561001057600080fd5b50610a0d806100206000396000f3fe608060405234801561001057600080fd5b50600436106100625760003560e01c80631a8d1b1c146100675780631e2e46e01461009757806333f707c1146100c757806359d3c1e6146100f7578063b2e0100c14610127578063e5aa3d5814610157575b600080fd5b610081600480360381019061007c9190610804565b610187565b60405161008e91906108a1565b60405180910390f35b6100b160048036038101906100ac9190610804565b6101a0565b6040516100be91906108a1565b60405180910390f35b6100e160048036038101906100dc9190610804565b6101c9565b6040516100ee91906108a1565b60405180910390f35b610111600480360381019061010c91906108bc565b6101e8565b60405161011e91906108a1565b60405180910390f35b610141600480360381019061013c9190610804565b6101f9565b60405161014e91906108a1565b60405180910390f35b610171600480360381019061016c9190610804565b610228565b60405161017e91906108a1565b60405180910390f35b60006101946064846102a790919063ffffffff16565b82029050919050565b60006012905060126006846101b69190610918565b6101c09190610918565b915050919050565b60006101d58383610301565b6101e1908361033d90919063ffffffff16565b905092915050565b60008183610196919061096c565b60008060019050600084905060005b8381101561021d5761020f8382610301565b91508080610215906109a0565b915050610207565b508091505092915050565b600061023560648461037990919063ffffffff16565b8290506102438184610301565b61024f908361033d90919063ffffffff16565b905061026a6109600861037990919063ffffffff16565b915050919050565b600080831415610289576000905061029c565b600082848561029991906109e9565b0490505b92915050565b6000808314156102ba5760009050610296565b60008284836102c991906109e9565b6102d39190610a1a565b90505b92915050565b60008082846102e991906109e9565b90506000838152602090905092915050505b92915050565b60008082846103109190610a1a565b90508385610320919061096c565b61032a9190610a1a565b90505b92915050565b60008083148061034f575060008284610350919061096c565b115b1561035e5760009050610373565b600082848661036e91906109e9565b0490505b92915050565b60008083141561038c5760009050610296565b600082848561039b91906109e9565b905092915050565b6000813590506103b381610a4f565b92915050565b6000813590506103c881610a66565b92915050565b6000813590506103dd81610a7d565b92915050565b600080604083850312156103fa576103f9610a94565b5b6000610408858286016103a4565b9250506020610419858286016103a4565b9150509250929050565b60008060006060848603121561043c5761043b610a94565b5b600061044a868287016103a4565b935050602061045b868287016103a4565b925050604061046c868287016103a4565b9150509250925092565b60008060006060848603121561048f5761048e610a94565b5b600061049d868287016103a4565b93505060206104ae868287016103a4565b92505060406104bf868287016103a4565b9150509250925092565b600080604083850312156104e2576104e1610a94565b5b60006104f0858286016103a4565b9250506020610501858286016103a4565b9150509250929050565b60006020828403121561052357610522610a94565b5b6000610531848285016103a4565b91505092915050565b60006020828403121561055057610552610a94565b5b600061055e848285016103b9565b91505092915050565b60006020828403121561057d5761057c610a94565b5b600061058b848285016103ce565b91505092915050565b61059d81610a99565b82525050565b6105ac81610a99565b82525050565b6105bb81610aab565b82525050565b6105ca81610aab565b82525050565b60006105db82610a99565b9150610a9983610a99565b92508282039050818111156105f4576105f3610abd565b5b92915050565b600061060582610a99565b9150610a9983610a99565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff048311821515161561063e5761063d610abd565b5b828202905092915050565b600061065482610a99565b9150610a9983610a99565b9250828210156106675761066661061c565b5b828203905092915050565b600061067d82610a99565b9150610a9983610a99565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff04831182151516156106b6576106b5610abd565b5b828202905092915050565b60006106cc82610a99565b9150610a9983610a99565b9250828202610a9983610a99565b92506106eb82610a99565b91508282039050818111156107035761070261061c565b5b92915050565b600061071482610a99565b9150610a9983610a99565b92508261072483610a99565b91508282039050818111156107395761073861061c565b5b92915050565b600061074a82610a99565b9150610a9983610a99565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff04831182151516156107835761078261061c565b5b828202905092915050565b600061079982610a99565b9150610a9983610a99565b92508282039050818111156107b2576107b1610abd565b5b92915050565b60006107c382610a99565b9150610a9983610a99565b9250828210156107d6576107d5610abd565b5b828203905092915050565b60006107ec82610a99565b9150610a9983610a99565b9250828202610a9983610a99565b60008135905061080e81610a4f565b92915050565b60006020828403121561082a57610829610a94565b5b6000610838848285016107ff565b91505092915050565b60006020828403121561085757610856610a94565b5b6000610865848285016107ff565b91505092915050565b60006020828403121561088457610883610a94565b5b6000610892848285016107ff565b91505092915050565b61089b81610a99565b82525050565b60006020820190506108b66000830184610594565b92915050565b600080604083850312156108d3576108d2610a94565b5b60006108e1858286016107ff565b92505060206108f2858286016107ff565b9150509250929050565b600060208201905061091360008301846105c1565b92915050565b600061092382610a99565b9150610a9983610a99565b9250828202610a9983610a99565b600061094382610a99565b9150610a9983610a99565b9250828203610a9983610a99565b600061096682610a99565b9150610a9983610a99565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff04831182151516156109a5576109a4610abd565b5b828202905092915050565b60006109ab82610a99565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8214156109de576109dd610abd565b5b600182019050919050565b60006109f482610a99565b9150610a9983610a99565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615610a2d57610a2c610abd565b5b828202905092915050565b6000610a4382610a99565b9150610a9983610a99565b9250828202610a9983610a99565b610a5881610a99565b8114610a6357600080fd5b50565b610a6f81610a99565b8114610a7a57600080fd5b50565b610a8681610a99565b8114610a9157600080fd5b50565b600080fd5b6000819050919050565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fdfea2646970667358221220c5d2460186f048cd44bcdeba2a1f6a66e3c30cc0485903f2f9e6242c0c64658964736f6c63430008070033";
    let bytecode = Bytes::from(hex::decode(bytecode_hex)?);
    
    println!("Analyzing bytecode for precision vulnerabilities...\n");
    
    // Create a verifier with custom configuration that focuses on precision vulnerabilities
    let config = ConfigManager::builder()
        .detect_precision_loss(true)
        .detect_arithmetic(true)  // Related to precision issues
        .detect_flash_loan(false) // Disable unrelated checks
        .detect_reentrancy(false)
        .detect_cross_contract_reentrancy(false)
        .detect_access_control(false)
        .detect_delegate_call(false)
        .detect_oracle_manipulation(false)
        .detect_governance(false)
        .detect_gas_griefing(false)
        .detect_event_emission(false)
        .detect_front_running(false)
        .build();
    
    let verifier = EVMVerify::with_config(config);
    
    // Analyze the bytecode specifically for precision vulnerabilities
    let vulnerabilities = verifier.analyze_precision_vulnerabilities(bytecode.clone())?;
    
    // Display results
    if vulnerabilities.is_empty() {
        println!("No precision vulnerabilities detected.");
    } else {
        println!("Found {} precision vulnerabilities:", vulnerabilities.len());
        for (i, vuln) in vulnerabilities.iter().enumerate() {
            println!("\nVulnerability #{}", i + 1);
            println!("  Type: {:?}", vuln.kind);
            println!("  PC: {}", vuln.pc);
            println!("  Description: {}", vuln.description);
            println!("  Severity: {:?}", vuln.severity);
        }
    }
    
    // Also perform a full analysis
    println!("\nPerforming full contract analysis...");
    let report = verifier.analyze_bytecode(bytecode)?;
    
    println!("\nFull Analysis Report:");
    println!("  Contract size: {} bytes", report.contract_size);
    println!("  Total vulnerabilities: {}", report.vulnerabilities.len());
    
    for (i, vuln) in report.vulnerabilities.iter().enumerate() {
        println!("\nVulnerability #{}", i + 1);
        println!("  Title: {}", vuln.title);
        println!("  Type: {:?}", vuln.vulnerability_type);
        println!("  Severity: {:?}", vuln.severity);
        println!("  Description: {}", vuln.description);
        println!("  Recommendation: {}", vuln.recommendation);
    }
    
    Ok(())
}
