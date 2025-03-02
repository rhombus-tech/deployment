use std::path::PathBuf;
use clap::Parser;
use anyhow::Result;
use verify::proofs::{MemorySafetyProperty, Property};
use wasmparser::WasmFeatures;
use std::fs;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the WASM file to analyze
    #[arg(short, long)]
    wasm_file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Read the WASM file
    let wasm = fs::read(&args.wasm_file)?;
    
    // Create a memory safety property
    let memory_property = MemorySafetyProperty::new();
    
    // Verify the property
    let features = WasmFeatures::default();
    let memory_proof = memory_property.verify(&wasm, &features)?;
    
    // Print the results
    println!("Memory Safety Analysis:");
    println!("  • Bounds checked: {}", if memory_proof.bounds_checked { "✓" } else { "✗" });
    println!("  • Leak free: {}", if memory_proof.leak_free { "✓" } else { "✗" });
    println!("  • Access safety: {}", if memory_proof.access_safety { "✓" } else { "✗" });
    
    if memory_proof.bounds_checked && memory_proof.leak_free && memory_proof.access_safety {
        println!("\n✅ WASM module satisfies all safety properties!");
    } else {
        println!("\n❌ WASM module does not satisfy all safety properties.");
    }
    
    Ok(())
}
