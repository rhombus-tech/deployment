pub mod analyzer;
pub mod memory;
pub mod types;
pub mod security;
pub mod access_control;
pub mod analyzer_unchecked_calls;
pub mod analyzer_txorigin;
pub mod analyzer_gas_limit;
pub mod analyzer_reentrancy;
pub mod analyzer_underflow;
pub mod analyzer_overflow;
// pub mod analyzer_tx_origin; // Commented out until file is created
pub mod analyzer_arithmetic;
pub mod analyzer_self_destruct;
pub mod analyzer_access_control;
pub mod analyzer_timestamp;
pub mod analyzer_blocknumber;
pub mod analyzer_externalcalls;
pub mod analyzer_flashloan;
pub mod opcodes;
#[cfg(test)]
pub mod tests;

pub use analyzer::BytecodeAnalyzer;
pub use memory::*;
pub use types::*;
pub use security::*;
pub use access_control::AccessControlAnalyzer;
pub use analyzer_timestamp::TimestampDependencyDetector;
pub use analyzer_blocknumber::BlockNumberDependencyDetector;
pub use analyzer_externalcalls::ExternalCallDetector;
