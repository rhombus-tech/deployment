use anyhow::Result;

/// Memory safety property verification
pub mod memory;
/// EVM bytecode analysis
pub mod bytecode;
/// Pipeline for analyzing EVM bytecode
pub mod pipeline;

pub use memory::MemoryAnalyzer;
pub use bytecode::BytecodeAnalyzer;
pub use pipeline::AnalysisPipeline;

/// Common trait for all EVM properties that can be verified
pub trait Property {
    type Proof;
    
    /// Verify a property for a given EVM bytecode
    fn verify(&self, bytecode: &[u8]) -> Result<Self::Proof>;
}
