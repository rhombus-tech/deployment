pub mod analyzer;
pub mod circuits;
pub mod prover;

// Re-export specific modules instead of using glob imports
pub use analyzer::pipeline;
pub use analyzer::memory;
pub use analyzer::bytecode;
pub use prover::*;

#[cfg(test)]
mod tests;
