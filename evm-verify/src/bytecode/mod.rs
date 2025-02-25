pub mod memory;
pub mod types;
#[cfg(test)]
pub mod tests;

use anyhow::Result;
use ethers::types::U256;

use self::memory::MemoryAnalyzer;
use self::types::{ConstructorAnalysis, RuntimeAnalysis};

/// Bytecode analyzer for contract deployment
#[derive(Debug)]
pub struct BytecodeAnalyzer {
    /// Program counter
    pc: usize,
    /// Memory analyzer
    memory: MemoryAnalyzer,
    /// Constructor analysis
    constructor: ConstructorAnalysis,
    /// Runtime analysis
    runtime: RuntimeAnalysis,
}

impl BytecodeAnalyzer {
    /// Create new bytecode analyzer
    pub fn new() -> Self {
        Self {
            pc: 0,
            memory: MemoryAnalyzer::new(),
            constructor: ConstructorAnalysis::default(),
            runtime: RuntimeAnalysis::default(),
        }
    }

    /// Record memory allocation
    pub fn record_memory_allocation(&mut self, offset: U256, size: U256) -> Result<()> {
        self.memory.record_allocation(offset, size, self.pc);
        Ok(())
    }

    /// Record memory access
    pub fn record_memory_access(&mut self, offset: U256, size: U256, write: bool) -> Result<()> {
        self.memory.record_access(offset, size, self.pc, write);
        Ok(())
    }

    /// Get constructor analysis
    pub fn get_constructor(&self) -> &ConstructorAnalysis {
        &self.constructor
    }

    /// Get runtime analysis
    pub fn get_runtime(&self) -> &RuntimeAnalysis {
        &self.runtime
    }

    /// Get memory analyzer
    pub fn get_memory(&self) -> &MemoryAnalyzer {
        &self.memory
    }
}
