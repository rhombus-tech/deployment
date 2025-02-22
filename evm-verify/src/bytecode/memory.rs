use ethers::types::U256;

use crate::bytecode::types::{MemoryAccess, MemoryAllocation};

/// Memory analyzer for tracking memory operations
#[derive(Debug, Default)]
pub struct MemoryAnalyzer {
    /// Memory accesses
    pub accesses: Vec<MemoryAccess>,
    /// Memory allocations
    pub allocations: Vec<MemoryAllocation>,
}

impl MemoryAnalyzer {
    /// Create new memory analyzer
    pub fn new() -> Self {
        Self::default()
    }

    /// Record memory access
    pub fn record_access(&mut self, offset: U256, size: U256, pc: usize, write: bool) {
        self.accesses.push(MemoryAccess {
            offset,
            size,
            pc,
            write,
        });
    }

    /// Record memory allocation
    pub fn record_allocation(&mut self, offset: U256, size: U256, pc: usize) {
        self.allocations.push(MemoryAllocation {
            offset,
            size,
            pc,
        });
    }

    /// Clear analysis state
    pub fn clear(&mut self) {
        self.accesses.clear();
        self.allocations.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_analyzer() {
        let mut analyzer = MemoryAnalyzer::new();

        // Record memory access
        analyzer.record_access(
            U256::from(0),
            U256::from(32),
            0,
            false,
        );

        // Record memory allocation
        analyzer.record_allocation(
            U256::from(0),
            U256::from(64),
            0,
        );

        // Check recorded operations
        assert_eq!(analyzer.accesses.len(), 1);
        let access = analyzer.accesses.get(0).unwrap();
        assert_eq!(access.offset, U256::from(0));
        assert_eq!(access.size, U256::from(32));
        assert_eq!(access.pc, 0);
        assert!(!access.write);

        assert_eq!(analyzer.allocations.len(), 1);
        let allocation = analyzer.allocations.get(0).unwrap();
        assert_eq!(allocation.offset, U256::from(0));
        assert_eq!(allocation.size, U256::from(64));
        assert_eq!(allocation.pc, 0);

        // Clear state
        analyzer.clear();
        assert!(analyzer.accesses.is_empty());
        assert!(analyzer.allocations.is_empty());
    }
}
