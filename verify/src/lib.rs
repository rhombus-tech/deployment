// EVM Verify Library - Core verification functionality
pub mod circuits;
pub mod parser;
pub mod proofs;
pub mod prover;
pub mod zk;
pub mod tee;

#[cfg(test)]
pub mod tests;

use anyhow::Result;
use wasmparser::WasmFeatures;

pub fn verify_wasm(wasm: &[u8]) -> Result<()> {
    // Basic WASM validation
    wasmparser::validate(wasm)?;
    Ok(())
}

pub use prover::{
    generate_combined_keys,
    generate_combined_proof,
    verify_combined_proof,
};
