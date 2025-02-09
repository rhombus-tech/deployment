use wasmparser::WasmFeatures;
use anyhow::Result;

/// Memory safety property verification
pub mod memory;
/// Type correctness verification
pub mod types;
/// Resource usage verification
pub mod resources;
/// WASM module verification
mod wasm;
/// Pipeline for analyzing WASM modules
pub mod pipeline;

pub use memory::MemoryAnalyzer;
pub use wasm::WasmAnalyzer;
pub use pipeline::AnalysisPipeline;

/// Common trait for all WASM properties that can be verified
pub trait Property {
    type Proof;
    
    /// Verify a property for a given WASM module
    fn verify(&self, wasm: &[u8], features: &WasmFeatures) -> Result<Self::Proof>;
}
