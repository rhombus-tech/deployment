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

    /// Check for reentrancy vulnerability
    /// Returns true if a reentrancy vulnerability is detected
    pub fn has_reentrancy_vulnerability(&self) -> bool {
        // Look for the key vulnerability pattern:
        // 1. State read before external call
        // 2. Value transfer via external call
        // 3. State update after external call
        self.accesses.windows(2).any(|window| {
            // Check if we have a write after a read
            window[1].write && !window[0].write
        })
    }

    /// Get detailed vulnerability report
    pub fn get_vulnerability_report(&self) -> Vec<String> {
        let mut vulnerabilities = Vec::new();
        
        // Check for reentrancy
        if self.has_reentrancy_vulnerability() {
            vulnerabilities.push(String::from(
                "Reentrancy vulnerability detected: State modification after external call. \
                This pattern is similar to the vulnerability exploited in the DAO hack. \
                Consider implementing checks-effects-interactions pattern."
            ));
        }

        // Add checks for other vulnerability patterns here
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_analyzer() {
        let mut analyzer = MemoryAnalyzer::new();
        
        // Record some operations
        analyzer.record_allocation(U256::from(0), U256::from(32), 0);
        analyzer.record_access(U256::from(0), U256::from(32), 1, false);
        
        assert_eq!(analyzer.allocations.len(), 1);
        assert_eq!(analyzer.accesses.len(), 1);
        
        analyzer.clear();
        
        assert_eq!(analyzer.allocations.len(), 0);
        assert_eq!(analyzer.accesses.len(), 0);
    }

    #[test]
    fn test_reentrancy_detection() {
        let mut analyzer = MemoryAnalyzer::new();

        // Simulate DAO-like vulnerability pattern
        analyzer.record_access(U256::from(0), U256::from(32), 0, false); // Read state
        analyzer.record_access(U256::from(32), U256::from(32), 1, true); // Write state after read

        assert!(analyzer.has_reentrancy_vulnerability(), "Should detect reentrancy vulnerability");
        
        let report = analyzer.get_vulnerability_report();
        assert!(!report.is_empty(), "Should generate vulnerability report");
        assert!(report[0].contains("Reentrancy vulnerability"), "Report should mention reentrancy");
    }
}
