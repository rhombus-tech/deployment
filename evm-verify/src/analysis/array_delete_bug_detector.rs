use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArrayDeleteBugVulnerability {
    DeleteNestedStruct { description: String, location: usize, confidence: f32 },
    DeleteMappingInStruct { description: String, location: usize },
    DeleteDynamicArray { description: String, location: usize },
}

pub struct ArrayDeleteBugDetector {
    bytecode: Vec<u8>,
}

impl ArrayDeleteBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ArrayDeleteBugVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // DELETE operation in Solidity uses SSTORE with 0
        // But for complex types, it doesn't clear nested structures
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.is_delete_operation(i) {
                // Check if deleting complex structure
                if self.deletes_complex_structure(i, i + 60) {
                    vulnerabilities.push(ArrayDeleteBugVulnerability::DeleteNestedStruct {
                        description: "delete on struct with nested mapping/array doesn't clear nested data - storage corruption".to_string(),
                        location: i,
                        confidence: 0.75,
                    });
                }
                
                // Check for array with struct elements
                if self.deletes_array_of_structs(i, i + 60) {
                    vulnerabilities.push(ArrayDeleteBugVulnerability::DeleteDynamicArray {
                        description: "delete on array of structs doesn't clear struct contents - memory leak".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_delete_operation(&self, location: usize) -> bool {
        if location + 10 > self.bytecode.len() {
            return false;
        }
        
        // Pattern: PUSH1 0x00 → SSTORE (storing zero)
        self.bytecode[location] == 0x60 && 
        self.bytecode[location + 1] == 0x00 &&
        self.bytecode[location..location + 10].contains(&0x55)
    }
    
    fn deletes_complex_structure(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Complex structure indicated by multiple KECCAK256 (for mapping keys)
        // or multiple sequential storage slots
        let keccak_count = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x20)
            .count();
        
        keccak_count >= 2
    }
    
    fn deletes_array_of_structs(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Array length stored separately, elements have struct layout
        // Look for: array length SLOAD, then element deletions
        let has_length_load = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        let has_multiple_sstores = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x55)
            .count() > 1;
        
        has_length_load && has_multiple_sstores
    }
}
