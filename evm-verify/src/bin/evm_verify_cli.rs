use std::fs;
use std::path::PathBuf;
use anyhow::Result;
use clap::{Parser, Subcommand};
use evm_verify::api::unified::UnifiedVerifier;
use hex;

/// EVM Verify CLI
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a smart contract for vulnerabilities
    Analyze {
        /// Path to the bytecode file
        #[clap(short, long)]
        file: PathBuf,
        
        /// Type of analysis to perform (pcc, pcd, or both)
        #[clap(short, long, default_value = "both")]
        analysis_type: String,
    },
    
    /// Generate a proof for a smart contract
    GenerateProof {
        /// Path to the bytecode file
        #[clap(short, long)]
        file: PathBuf,
        
        /// Path to the output file
        #[clap(short, long)]
        output: PathBuf,
        
        /// Type of proof to generate (pcc or pcd)
        #[clap(short, long)]
        proof_type: String,
    },
    
    /// Verify a proof for a smart contract
    VerifyProof {
        /// Path to the bytecode file
        #[clap(short, long)]
        file: PathBuf,
        
        /// Path to the proof file
        #[clap(short, long)]
        proof: PathBuf,
        
        /// Type of proof to verify (pcc or pcd)
        #[clap(short, long)]
        proof_type: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match &cli.command {
        Commands::Analyze { file, analysis_type } => {
            analyze_bytecode(file.clone(), analysis_type.clone())?;
        },
        Commands::GenerateProof { file, output, proof_type } => {
            generate_proof(file.clone(), output.clone(), proof_type.clone())?;
        },
        Commands::VerifyProof { file, proof, proof_type } => {
            verify_proof(file.clone(), proof.clone(), proof_type.clone())?;
        },
    }
    
    Ok(())
}

fn analyze_bytecode(file: PathBuf, analysis_type: String) -> Result<()> {
    // Read bytecode from file
    let bytecode_hex = fs::read_to_string(file)?;
    let bytecode_bytes = hex::decode(bytecode_hex.trim_start_matches("0x"))?;
    
    // Create a unified verifier
    let verifier = match analysis_type.as_str() {
        "pcc" => UnifiedVerifier::with_config(false, true),
        "pcd" => UnifiedVerifier::with_config(true, false),
        _ => UnifiedVerifier::new(),
    };
    
    // Analyze the bytecode
    let report = verifier.analyze_bytecode(&bytecode_bytes)?;
    
    // Print the results
    println!("Analysis Report:");
    println!("Contract Size: {} bytes", report.contract_size);
    println!("Vulnerabilities Found: {}", report.vulnerabilities.len());
    
    for (i, vulnerability) in report.vulnerabilities.iter().enumerate() {
        println!("Vulnerability #{}: {}", i + 1, vulnerability.title);
        println!("  Description: {}", vulnerability.description);
        println!("  Severity: {:?}", vulnerability.severity);
        println!("  Type: {:?}", vulnerability.vulnerability_type);
        println!("  Recommendation: {}", vulnerability.recommendation);
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
            let proof_bytes = proof;
            
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
                // In a real implementation, this would extract the proof and verifying key from proof_bytes
                // For now, we just use the raw bytes
                (proof_bytes.clone(), vec![0u8; 32])
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
                
                if !result.vulnerabilities.is_empty() {
                    println!("Vulnerabilities found:");
                    for (i, vulnerability) in result.vulnerabilities.iter().enumerate() {
                        println!("  {}. {}", i + 1, vulnerability);
                    }
                }
            }
        },
        _ => {
            println!("Invalid proof type: {}", proof_type);
        },
    }
    
    Ok(())
}
