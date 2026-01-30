/// Assembly Undefined Behavior Detector
/// Detects dangerous inline assembly patterns that can cause undefined behavior

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyUndefinedBehavior {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct AssemblyUndefinedBehaviorDetector {
    bytecode: Vec<u8>,
}

impl AssemblyUndefinedBehaviorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<AssemblyUndefinedBehavior> {
        let mut vulns = Vec::new();
        
        vulns.extend(self.detect_invalid_opcodes());
        vulns.extend(self.detect_stack_underflow());
        vulns.extend(self.detect_memory_overflow());
        vulns.extend(self.detect_unsafe_memory_access());
        
        vulns
    }
    
    fn detect_invalid_opcodes(&self) -> Vec<AssemblyUndefinedBehavior> {
        let mut vulns = Vec::new();
        
        // Opcodes that are invalid or dangerous
        let invalid_ops = vec![0xFE, 0xFF]; // INVALID, SELFDESTRUCT (deprecated)
        
        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if invalid_ops.contains(&opcode) {
                vulns.push(AssemblyUndefinedBehavior {
                    vulnerability_type: "Invalid Opcode".to_string(),
                    severity: "High".to_string(),
                    location: i,
                    description: format!("Invalid opcode 0x{:02X} causes undefined behavior", opcode),
                    remediation: "Remove invalid opcodes from assembly".to_string(),
                });
            }
        }
        vulns
    }
    
    fn detect_stack_underflow(&self) -> Vec<AssemblyUndefinedBehavior> {
        let mut vulns = Vec::new();
        let mut stack_depth = 0i32;
        
        for (i, &opcode) in self.bytecode.iter().enumerate() {
            // Track stack operations
            match opcode {
                0x60..=0x7F => stack_depth += 1, // PUSH
                0x50 => stack_depth -= 1, // POP
                0x01..=0x1D => {  // Arithmetic ops
                    stack_depth -= 1; // Most consume 2, produce 1
                    if stack_depth < 0 {
                        vulns.push(AssemblyUndefinedBehavior {
                            vulnerability_type: "Stack Underflow".to_string(),
                            severity: "Critical".to_string(),
                            location: i,
                            description: "Stack underflow - consuming more items than available".to_string(),
                            remediation: "Ensure stack has sufficient items before operations".to_string(),
                        });
                    }
                }
                _ => {}
            }
        }
        vulns
    }
    
    fn detect_memory_overflow(&self) -> Vec<AssemblyUndefinedBehavior> {
        let mut vulns = Vec::new();
        
        // MSTORE/MLOAD with very large offsets
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x52 || self.bytecode[i] == 0x51 { // MSTORE/MLOAD
                // Check for large PUSH before it
                for j in i.saturating_sub(5)..i {
                    if self.bytecode[j] >= 0x7A { // PUSH27 or larger
                        vulns.push(AssemblyUndefinedBehavior {
                            vulnerability_type: "Memory Overflow Risk".to_string(),
                            severity: "Medium".to_string(),
                            location: i,
                            description: "Memory access with very large offset can cause overflow".to_string(),
                            remediation: "Validate memory offsets in assembly".to_string(),
                        });
                    }
                }
            }
        }
        vulns
    }
    
    fn detect_unsafe_memory_access(&self) -> Vec<AssemblyUndefinedBehavior> {
        let mut vulns = Vec::new();
        
        // MSTORE/MLOAD without bounds checking
        for i in 0..self.bytecode.len() {
            if matches!(self.bytecode[i], 0x51 | 0x52) {
                vulns.push(AssemblyUndefinedBehavior {
                    vulnerability_type: "Unchecked Memory Access".to_string(),
                    severity: "Low".to_string(),
                    location: i,
                    description: "Memory access in assembly without explicit bounds check".to_string(),
                    remediation: "Add bounds checking for memory operations".to_string(),
                });
            }
        }
        vulns
    }
}
