use std::path::PathBuf;
use clap::Parser;
use anyhow::Result;
use verify::proofs::{MemorySafetyProperty, Property};
use wasmparser::WasmFeatures;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the WASM file to analyze
    #[arg(short, long)]
    wasm_file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Read WASM file
    let wasm = std::fs::read(&args.wasm_file)?;
    
    // Create property verifiers
    let memory_safety = MemorySafetyProperty::new();
    
    println!("Verifying WASM module...");
    
    // Verify memory safety
    let memory_proof = memory_safety.verify(&wasm, &WasmFeatures::default())?;
    
    println!("\nVerification Results:");
    println!("  • Memory safety: {}", if memory_proof.bounds_checked { "✓" } else { "✗" });
    println!("  • Leak free: {}", if memory_proof.leak_free { "✓" } else { "✗" });
    println!("  • Access safety: {}", if memory_proof.access_safety { "✓" } else { "✗" });
    
    if memory_proof.bounds_checked && memory_proof.leak_free && memory_proof.access_safety {
        println!("\n✅ WASM module satisfies all safety properties!");
    } else {
        println!("\n❌ WASM module failed some safety checks!");
    }

    Ok(())
}
