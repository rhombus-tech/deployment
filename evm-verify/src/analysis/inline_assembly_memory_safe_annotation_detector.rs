use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemorySafeAnnotationVulnerability {
    FalseMemorySafeAnnotation { description: String, location: usize, confidence: f32 },
    MemoryModificationInSafeBlock { description: String, location: usize, confidence: f32 },
}

pub struct InlineAssemblyMemorySafeAnnotationDetector {
    bytecode: Vec<u8>,
}

impl InlineAssemblyMemorySafeAnnotationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<MemorySafeAnnotationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_false_memory_safe());
        vulnerabilities
    }
    
    fn detect_false_memory_safe(&self) -> Vec<MemorySafeAnnotationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Solidity 0.8.13+ allows `assembly ("memory-safe")` annotation
        // If annotation claims memory-safe but code modifies memory, optimizer bugs can occur
        // In bytecode: Look for MSTORE/MSTORE8/MLOAD in regions that should be optimizer-friendly
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let section = &self.bytecode[i..std::cmp::min(i + 20, self.bytecode.len())];
            
            // Pattern: Memory operations that modify free memory pointer region
            let has_mstore = section.contains(&0x52); // MSTORE
            let has_mstore8 = section.contains(&0x53); // MSTORE8
            
            // Check if modifying free memory pointer (0x40)
            let modifies_free_ptr = section.windows(3).any(|w| {
                w[0] == 0x60 && w[1] == 0x40 && // PUSH1 0x40
                (w[2] == 0x52 || w[2] == 0x51) // MSTORE or MLOAD
            });
            
            if (has_mstore || has_mstore8) && modifies_free_ptr {
                vulnerabilities.push(MemorySafeAnnotationVulnerability::FalseMemorySafeAnnotation {
                    description: format!("Assembly block at PC {} modifies free memory pointer (0x40). Solidity 0.8.13+: If marked `assembly (\"memory-safe\")`, optimizer assumes no memory modifications. FALSE annotation → optimizer reorders code → memory corruption. Only mark truly read-only assembly as memory-safe.", i),
                    location: i,
                    confidence: 0.87,
                });
            }
            
            // Check for memory expansion without proper allocation
            let has_memory_expansion = section.windows(5).any(|w| {
                w.contains(&0x59) && // MSIZE
                w.contains(&0x52)    // MSTORE after MSIZE check
            });
            
            if has_memory_expansion {
                vulnerabilities.push(MemorySafeAnnotationVulnerability::MemoryModificationInSafeBlock {
                    description: format!("Assembly at PC {} expands memory with MSTORE. If block marked memory-safe, optimizer may assume fixed memory layout. Risk: Gas optimizations break, memory corruption. Remove \"memory-safe\" annotation if any MSTORE/MSTORE8 present.", i),
                    location: i,
                    confidence: 0.84,
                });
            }
        }
        
        vulnerabilities
    }
}
