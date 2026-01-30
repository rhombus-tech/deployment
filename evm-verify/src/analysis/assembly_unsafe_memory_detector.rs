use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssemblyUnsafeMemoryVulnerability {
    UncheckedMemoryAccess { description: String, location: usize, confidence: f32 },
}

pub struct AssemblyUnsafeMemoryDetector {
    bytecode: Vec<u8>,
}

impl AssemblyUnsafeMemoryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AssemblyUnsafeMemoryVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_assembly_memory_operations() && !self.validates_memory_bounds() {
            vulnerabilities.push(AssemblyUnsafeMemoryVulnerability::UncheckedMemoryAccess {
                description: "Assembly memory operations without bounds checking - unsafe memory access".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        vulnerabilities
    }
    
    fn has_assembly_memory_operations(&self) -> bool {
        let mload_count = self.bytecode.iter().filter(|&&b| b == 0x51).count();
        let mstore_count = self.bytecode.iter().filter(|&&b| b == 0x52).count();
        mload_count > 5 || mstore_count > 5
    }
    
    fn validates_memory_bounds(&self) -> bool {
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let msize_count = self.bytecode.iter().filter(|&&b| b == 0x59).count();
        lt_count > 2 && msize_count > 0
    }
}
