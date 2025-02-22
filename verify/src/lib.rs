extern crate ark_relations;

pub mod circuits;
pub mod parser;
pub mod proofs;
pub mod prover;
pub mod zk;

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
