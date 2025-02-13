pub mod proofs;
pub mod parser;
mod circuits;
pub mod prover;

pub use parser::WasmAnalyzer;
pub use prover::{
    generate_combined_keys,
    generate_combined_proof,
    verify_combined_proof,
};
