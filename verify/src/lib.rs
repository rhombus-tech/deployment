extern crate ark_relations;

pub mod proofs;
pub mod parser;
mod circuits;
pub mod prover;

use anyhow::Result;
use parser::Parser;

pub fn verify_wasm(wasm: &[u8]) -> Result<()> {
    let module = walrus::Module::from_buffer(wasm)?;
    let mut parser = Parser::new(module);
    
    // Get all function IDs to validate
    let func_ids: Vec<_> = parser.get_module().funcs.iter().map(|f| f.id()).collect();
    
    // Validate all functions
    for func_id in func_ids {
        parser.validate_function(func_id)?;
    }
    
    Ok(())
}

pub use prover::{
    generate_combined_keys,
    generate_combined_proof,
    verify_combined_proof,
};
