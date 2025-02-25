use ethers::types::U256;
use std::collections::HashMap;

use crate::bytecode::types::{MemoryAccess, MemoryAllocation};

/// Memory analyzer for tracking memory operations
#[derive(Debug, Default)]
pub struct MemoryAnalyzer {
    /// Memory accesses
    pub accesses: Vec<MemoryAccess>,
    /// Memory allocations
    pub allocations: Vec<MemoryAllocation>,
    /// Program counter of external call if any
    external_call_pc: Option<usize>,
    /// Program counter of arithmetic overflow if any
    arithmetic_overflow_pc: Option<usize>,
    /// State reads before external call
    state_reads: Vec<usize>,
    /// State writes after external call
    state_writes: Vec<usize>,
    /// Memory writes by offset
    memory_writes: HashMap<U256, bool>,
    /// Memory values by offset
    memory_values: HashMap<U256, U256>,
    /// Memory write ranges
    memory_ranges: Vec<(U256, U256)>, // (offset, size)
}

impl MemoryAnalyzer {
    /// Create new memory analyzer
    pub fn new() -> Self {
        Self {
            accesses: Vec::new(),
            allocations: Vec::new(),
            external_call_pc: None,
            arithmetic_overflow_pc: None,
            state_reads: Vec::new(),
            state_writes: Vec::new(),
            memory_writes: HashMap::new(),
            memory_values: HashMap::new(),
            memory_ranges: Vec::new(),
        }
    }

    /// Record memory access
    pub fn record_access(&mut self, offset: U256, size: U256, pc: usize, write: bool, value: Option<U256>) {
        self.accesses.push(MemoryAccess {
            offset,
            size,
            pc,
            write,
        });
        if write {
            // Record the write range
            self.record_write_range(offset, size);
            
            // For word-sized writes (32 bytes), record all offsets and value
            if size == U256::from(32) {
                if let Some(value) = value {
                    self.memory_values.insert(offset, value);
                }
                for i in 0..32 {
                    let curr_offset = offset + U256::from(i);
                    self.memory_writes.insert(curr_offset, true);
                }
            }
        }
    }

    /// Get memory value at offset
    pub fn get_memory_value(&self, offset: U256) -> Option<U256> {
        self.memory_values.get(&offset).copied()
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
        self.external_call_pc = None;
        self.arithmetic_overflow_pc = None;
        self.state_reads.clear();
        self.state_writes.clear();
        self.memory_writes.clear();
        self.memory_values.clear();
        self.memory_ranges.clear();
    }

    /// Record state read operation
    pub fn record_state_read(&mut self, pc: usize) {
        self.state_reads.push(pc);
    }

    /// Record state write operation
    pub fn record_state_write(&mut self, pc: usize) {
        self.state_writes.push(pc);
    }

    /// Record external call
    pub fn record_external_call(&mut self, pc: usize) {
        self.external_call_pc = Some(pc);
    }

    /// Record arithmetic overflow
    pub fn record_arithmetic_overflow(&mut self, pc: usize) {
        self.arithmetic_overflow_pc = Some(pc);
    }

    /// Record write at specific offset
    pub fn record_write_at_offset(&mut self, offset: U256) {
        self.memory_writes.insert(offset, true);
    }

    /// Record write range
    pub fn record_write_range(&mut self, offset: U256, size: U256) {
        // Merge overlapping or adjacent ranges
        let mut merged = false;
        for i in 0..self.memory_ranges.len() {
            let (range_offset, range_size) = self.memory_ranges[i];
            
            // Check if ranges overlap or are adjacent
            if offset <= range_offset + range_size && range_offset <= offset + size {
                // Merge ranges
                let new_offset = std::cmp::min(offset, range_offset);
                let new_size = std::cmp::max(
                    offset + size - new_offset,
                    range_offset + range_size - new_offset
                );
                self.memory_ranges[i] = (new_offset, new_size);
                merged = true;
                break;
            }
        }

        // If no merge occurred, add as new range
        if !merged {
            self.memory_ranges.push((offset, size));
        }

        // For word-sized writes, also record individual offsets
        if size == U256::from(32) {
            for i in 0..32 {
                let curr_offset = offset + U256::from(i);
                self.memory_writes.insert(curr_offset, true);
            }
        }
    }

    /// Check if memory at offset has been written to
    pub fn has_write_at_offset(&self, offset: U256) -> bool {
        // First check direct writes
        if self.memory_writes.contains_key(&offset) {
            return true;
        }

        // Then check ranges
        self.memory_ranges.iter().any(|(range_offset, range_size)| {
            offset >= *range_offset && offset < range_offset + range_size
        })
    }

    /// Check if a memory range has been fully written to
    pub fn has_write_at_range(&self, offset: U256, size: U256) -> bool {
        // For small ranges, check each offset individually
        if size <= U256::from(32) {
            for i in 0..size.as_u64() {
                let curr_offset = offset + U256::from(i);
                if !self.has_write_at_offset(curr_offset) {
                    return false;
                }
            }
            return true;
        }

        // For larger ranges, check if any write range fully contains this range
        self.memory_ranges.iter().any(|(range_offset, range_size)| {
            offset >= *range_offset && offset + size <= range_offset + range_size
        })
    }

    /// Check for reentrancy vulnerability
    /// Returns true if a reentrancy vulnerability is detected
    pub fn has_reentrancy_vulnerability(&self) -> bool {
        if let Some(call_pc) = self.external_call_pc {
            let mut state_writes_after_call = false;
            let mut state_reads_before_call = false;

            for &read_pc in &self.state_reads {
                if read_pc < call_pc {
                    state_reads_before_call = true;
                    break;
                }
            }

            for &write_pc in &self.state_writes {
                if write_pc > call_pc {
                    state_writes_after_call = true;
                    break;
                }
            }

            state_reads_before_call && state_writes_after_call
        } else {
            false
        }
    }

    /// Get detailed vulnerability report
    pub fn get_vulnerability_report(&self) -> Vec<String> {
        let mut vulnerabilities = Vec::new();
        
        // Check for arithmetic overflow
        if let Some(pc) = self.arithmetic_overflow_pc {
            vulnerabilities.push(format!(
                "Arithmetic overflow detected at pc {}. Consider using SafeMath or checked operations.",
                pc
            ));
        }
        
        // Check for reentrancy
        if self.has_reentrancy_vulnerability() {
            vulnerabilities.push(String::from(
                "Reentrancy vulnerability detected: State modification after external call. \
                This pattern is similar to the vulnerability exploited in the DAO hack. \
                Consider implementing checks-effects-interactions pattern."
            ));
        }

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
        analyzer.record_access(U256::from(0), U256::from(32), 1, false, None);
        
        assert_eq!(analyzer.allocations.len(), 1);
        assert_eq!(analyzer.accesses.len(), 1);
        
        analyzer.clear();
        
        assert_eq!(analyzer.allocations.len(), 0);
        assert_eq!(analyzer.accesses.len(), 0);
    }

    #[test]
    fn test_reentrancy_detection() {
        let mut analyzer = MemoryAnalyzer::new();

        // Simulate a read operation
        analyzer.record_state_read(0);
        
        // Simulate an external call
        analyzer.record_external_call(1);
        
        // Simulate a write operation after the call
        analyzer.record_state_write(2);
        
        assert!(analyzer.has_reentrancy_vulnerability());
        
        analyzer.clear();
        
        // Test safe pattern (write before call)
        analyzer.record_state_write(0);
        analyzer.record_external_call(1);
        analyzer.record_state_read(2);
        
        assert!(!analyzer.has_reentrancy_vulnerability());
    }

    #[test]
    fn test_arithmetic_overflow() {
        let mut analyzer = MemoryAnalyzer::new();
        
        // Record an overflow
        analyzer.record_arithmetic_overflow(1);
        
        let report = analyzer.get_vulnerability_report();
        assert!(!report.is_empty());
        assert!(report[0].contains("Arithmetic overflow"));
    }
}
