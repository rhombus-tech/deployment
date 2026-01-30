// VM module - Ethereum Virtual Machine implementation
// Provides step-by-step EVM execution for complete EF compliance

pub mod evm_interpreter;
pub mod evm_state_integration;
pub mod enhanced_evm_interpreter;
pub mod precompiles;

pub use evm_interpreter::*;
pub use evm_state_integration::*;
pub use enhanced_evm_interpreter::*;
pub use precompiles::*;
