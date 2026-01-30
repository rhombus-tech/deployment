use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DirtyBytesBugVulnerability {
    VulnerableVersion { description: String, location: usize, confidence: f32, version: String },
    ByteArrayCopy { description: String, location: usize },
}

pub struct DirtyBytesBugDetector {
    bytecode: Vec<u8>,
}

impl DirtyBytesBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DirtyBytesBugVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Dirty bytes bug affects Solidity < 0.8.15
        // Occurs with byte array copying and assembly
        if self.has_byte_array_operations() && self.has_assembly_usage() {
            vulnerabilities.push(DirtyBytesBugVulnerability::ByteArrayCopy {
                description: "Byte array copying with assembly - dirty bytes bug risk (Solidity < 0.8.15)".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn has_byte_array_operations(&self) -> bool {
        // CALLDATACOPY, CODECOPY, or RETURNDATACOPY
        self.bytecode.iter().any(|&b| b == 0x37 || b == 0x39 || b == 0x3E)
    }
    
    fn has_assembly_usage(&self) -> bool {
        // Inline assembly typically has unusual opcode patterns
        // Look for memory manipulation opcodes
        let mstore_count = self.bytecode.iter().filter(|&&b| b == 0x52).count();
        let mload_count = self.bytecode.iter().filter(|&&b| b == 0x51).count();
        mstore_count > 10 && mload_count > 10
    }
}
