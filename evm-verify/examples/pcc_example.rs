use evm_verify::pcc::{
    analyzer::{
        pipeline::AnalysisPipeline,
        memory::MemorySafetyProperty,
        bytecode::BytecodeSafetyProperty,
        Property,
    },
    circuits::{
        memory::MemorySafetyCircuit,
        bytecode::BytecodeSafetyCircuit,
    },
    prover::{
        generate_proving_key,
        generate_proof,
        verify_memory_proof,
        verify_bytecode_proof,
    },
};
use ark_bls12_381::Fr;
use ethers::types::Bytes;
use std::env;
use std::fs;

fn main() -> anyhow::Result<()> {
    // Get bytecode file from command line arguments
    let args: Vec<String> = env::args().collect();
    let bytecode_file = if args.len() > 1 {
        &args[1]
    } else {
        // Use a default sample bytecode if no file is provided
        println!("No bytecode file provided. Using sample bytecode.");
        // Sample bytecode: PUSH1 0x01, PUSH1 0x02, ADD, PUSH1 0x00, MSTORE, STOP
        let sample_bytecode = vec![0x60, 0x01, 0x60, 0x02, 0x01, 0x60, 0x00, 0x52, 0x00];
        analyze_bytecode(&sample_bytecode)?;
        return Ok(());
    };

    // Read bytecode from file
    println!("Reading bytecode from file: {}", bytecode_file);
    let bytecode_hex = fs::read_to_string(bytecode_file)?;
    let bytecode_hex = bytecode_hex.trim();
    
    // Convert hex to bytes
    let bytecode_bytes = if bytecode_hex.starts_with("0x") {
        hex::decode(&bytecode_hex[2..])?
    } else {
        hex::decode(bytecode_hex)?
    };
    
    // Analyze the bytecode
    analyze_bytecode(&bytecode_bytes)?;
    
    Ok(())
}

fn analyze_bytecode(bytecode: &[u8]) -> anyhow::Result<()> {
    println!("Analyzing bytecode of size {} bytes", bytecode.len());
    
    // Create analysis pipeline
    let mut pipeline = AnalysisPipeline::new();
    
    // Run analysis
    pipeline.analyze(bytecode)?;
    
    // Print analysis summary
    println!("\nAnalysis Results:");
    println!("{}", pipeline.get_summary());
    
    // Check if bytecode is safe
    if pipeline.is_safe() {
        println!("\nBytecode is SAFE. Generating proof...");
        
        // Generate proof
        pipeline.generate_proof(bytecode)?;
        
        println!("Proof generation successful!");
    } else {
        println!("\nBytecode is UNSAFE. Cannot generate proof.");
    }
    
    Ok(())
}
