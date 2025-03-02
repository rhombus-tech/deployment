use anyhow::Result;
use bincode;
use clap::{Parser, Subcommand};
use ethers::types::Bytes;
use std::fs;
use std::path::PathBuf;

use evm_verify::api::unified::UnifiedVerifier;

/// EVM Verify - A tool for verifying EVM bytecode
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze bytecode for vulnerabilities
    Analyze {
        /// Path to bytecode file
        #[clap(short, long)]
        file: PathBuf,
        
        /// Enable PCD verification
        #[clap(short, long)]
        pcd: bool,
        
        /// Enable PCC verification
        #[clap(short, long)]
        pcc: bool,
        
        /// Output format (json or text)
        #[clap(short, long, default_value = "text")]
        format: String,
    },
    
    /// Generate proof for bytecode
    Generate {
        /// Path to bytecode file
        #[clap(short, long)]
        file: PathBuf,
        
        /// Output file for proof
        #[clap(short, long)]
        output: PathBuf,
        
        /// Proof type (pcd or pcc)
        #[clap(short, long, default_value = "pcd")]
        proof_type: String,
    },
    
    /// Verify proof for bytecode
    Verify {
        /// Path to bytecode file
        #[clap(short, long)]
        file: PathBuf,
        
        /// Path to proof file
        #[clap(short, long)]
        proof: PathBuf,
        
        /// Proof type (pcd or pcc)
        #[clap(short, long, default_value = "pcd")]
        proof_type: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Analyze { file, pcd, pcc, format } => {
            analyze_bytecode(file, pcd, pcc, format)
        },
        Commands::Generate { file, output, proof_type } => {
            generate_proof(file, output, proof_type)
        },
        Commands::Verify { file, proof, proof_type } => {
            verify_proof(file, proof, proof_type)
        },
    }
}

fn analyze_bytecode(file: PathBuf, pcd: bool, pcc: bool, format: String) -> Result<()> {
    // Read bytecode from file
    let bytecode_hex = fs::read_to_string(file)?;
    let bytecode_bytes = hex::decode(bytecode_hex.trim_start_matches("0x"))?;
    
    // Create a unified verifier with the specified configuration
    let verifier = UnifiedVerifier::with_config(pcd, pcc);
    
    // Analyze the bytecode
    let report = verifier.analyze_bytecode(&bytecode_bytes)?;
    
    // Output the report
    match format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        },
        _ => {
            print_text_report(&report);
        },
    }
    
    Ok(())
}

fn generate_proof(file: PathBuf, output: PathBuf, proof_type: String) -> Result<()> {
    // Read bytecode from file
    let bytecode_hex = fs::read_to_string(file)?;
    let bytecode_bytes = hex::decode(bytecode_hex.trim_start_matches("0x"))?;
    
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    match proof_type.as_str() {
        "pcd" => {
            // Generate PCD proof
            let (proof, verifying_key) = verifier.generate_pcd_proof(&bytecode_bytes)?;
            
            // Serialize the proof
            #[cfg(feature = "accumulation")]
            let proof_bytes = pcd::accumulation::serialize_proof(&proof)?;
            
            #[cfg(not(feature = "accumulation"))]
            let proof_bytes = bincode::serialize(&(proof, verifying_key))?;
            
            // Write the proof to the output file
            fs::write(output, proof_bytes)?;
            
            println!("PCD proof generated successfully");
        },
        "pcc" => {
            // Generate PCC proof
            let proof = verifier.generate_pcc_proof(&bytecode_bytes)?;
            
            // Write the proof to the output file
            fs::write(output, proof)?;
            
            println!("PCC proof generated successfully");
        },
        _ => {
            println!("Invalid proof type: {}", proof_type);
        },
    }
    
    Ok(())
}

fn verify_proof(file: PathBuf, proof_file: PathBuf, proof_type: String) -> Result<()> {
    // Read bytecode from file
    let bytecode_hex = fs::read_to_string(file)?;
    let bytecode_bytes = hex::decode(bytecode_hex.trim_start_matches("0x"))?;
    
    // Read proof from file
    let proof_bytes = fs::read(proof_file)?;
    
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    match proof_type.as_str() {
        "pcd" => {
            // Deserialize the proof
            #[cfg(feature = "accumulation")]
            let (proof, verifying_key) = {
                use ark_bn254::{Bn254, Fr};
                use ark_groth16::Proof;
                
                let proof = pcd::accumulation::deserialize_proof(&proof_bytes)?;
                let verifying_key = vec![0u8; 32]; // In a real implementation, this would be extracted from the proof
                (proof, verifying_key)
            };
            
            #[cfg(not(feature = "accumulation"))]
            let (proof, verifying_key): (Vec<u8>, Vec<u8>) = bincode::deserialize(&proof_bytes)?;
            
            // Verify the proof
            let result = verifier.verify_pcd_proof(&bytecode_bytes, &proof, &verifying_key)?;
            
            if result.is_valid {
                println!("PCD proof verification successful");
            } else {
                println!("PCD proof verification failed");
            }
        },
        "pcc" => {
            // Verify the proof
            let result = verifier.verify_pcc_proof(&bytecode_bytes, &proof_bytes)?;
            
            if result.is_valid {
                println!("PCC proof verification successful");
            } else {
                println!("PCC proof verification failed");
            }
        },
        _ => {
            println!("Invalid proof type: {}", proof_type);
        },
    }
    
    Ok(())
}

fn print_text_report(report: &evm_verify::api::types::AnalysisReport) {
    println!("Analysis Report");
    println!("==============");
    println!("Timestamp: {}", report.timestamp);
    println!("Contract Size: {} bytes", report.contract_size);
    println!("Delegate Calls: {}", report.delegate_calls);
    println!("Memory Accesses: {}", report.memory_accesses);
    println!("Storage Accesses: {}", report.storage_accesses);
    println!();
    
    if report.vulnerabilities.is_empty() {
        println!("No vulnerabilities found");
    } else {
        println!("Vulnerabilities");
        println!("--------------");
        
        for (i, vulnerability) in report.vulnerabilities.iter().enumerate() {
            println!("{}. {} ({})", i + 1, vulnerability.title, vulnerability.severity);
            println!("   Description: {}", vulnerability.description);
            println!("   Type: {:?}", vulnerability.vulnerability_type);
            println!("   Location: {:?}", vulnerability.location);
            println!("   Recommendation: {}", vulnerability.recommendation);
            println!();
        }
    }
}
