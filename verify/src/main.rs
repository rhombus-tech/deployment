use std::fs;
use clap::Parser;
use anyhow::Result;
use pcc::analyzer::MemoryAnalyzer;
use pcc::circuits::memory::MemorySafetyCircuit;
use pcc::prover::{generate_proving_key, generate_proof, verify_memory_proof};
use ark_bls12_381::Fr;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the WASM file to analyze
    #[arg(short, long)]
    wasm_file: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Reading WASM file...");
    let wasm_binary = fs::read(&args.wasm_file)?;

    println!("Analyzing WASM binary...");
    let mut analyzer = MemoryAnalyzer::new();
    analyzer.analyze_wasm(&wasm_binary)?;

    println!("\nAnalysis Results:");
    let memory_accesses = analyzer.get_memory_accesses();
    println!("Memory accesses found: {}", memory_accesses.len());
    for access in memory_accesses.iter().take(100) {
        println!("  - {} at offset {}, size {}", 
            if !access.is_load { "Store" } else { "Load" },
            access.offset,
            access.size
        );
    }

    let allocations = analyzer.get_allocations();
    println!("\nAllocations found: {}", allocations.len());
    for alloc in allocations.iter() {
        println!("  - Address: {}, Size: {}, Freed: {}", 
            alloc.address,
            alloc.size,
            alloc.is_freed
        );
    }

    println!("\nGenerating memory safety proof...");
    
    // Convert analysis results to circuit inputs
    let accesses: Vec<_> = memory_accesses.iter()
        .map(|access| (access.offset as u64, access.size as u64))
        .collect();
    
    let allocations: Vec<_> = allocations.iter()
        .filter(|alloc| !alloc.is_freed)
        .map(|alloc| (alloc.address as u64, alloc.size as u64))
        .collect();

    let circuit = MemorySafetyCircuit::<Fr>::new(accesses, allocations);

    println!("Generating proving key...");
    let (proving_key, verifying_key) = generate_proving_key(&circuit)?;

    println!("Generating proof...");
    let proof = generate_proof(circuit, &proving_key)?;

    // Verify the proof
    let public_inputs = vec![];  // No public inputs needed for now
    let is_valid = verify_memory_proof(&proof, &verifying_key, &public_inputs)?;

    if is_valid {
        println!("Memory safety proof verified successfully!");
    } else {
        println!("Memory safety proof verification failed!");
    }

    Ok(())
}
