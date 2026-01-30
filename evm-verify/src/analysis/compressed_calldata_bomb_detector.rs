use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressedCalldataBombVulnerability {
    UnboundedDecompression { description: String, location: usize, confidence: f32 },
    NoSizeLimit { description: String, location: usize },
    RecursiveDecompression { description: String, location: usize },
}

pub struct CompressedCalldataBombDetector {
    bytecode: Vec<u8>,
}

impl CompressedCalldataBombDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CompressedCalldataBombVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.decompresses_calldata(i) {
                if !self.has_decompression_limit(i, i + 100) {
                    vulnerabilities.push(CompressedCalldataBombVulnerability::UnboundedDecompression {
                        description: "Calldata decompression without size limit - bomb attack vector".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                if self.is_recursive_decompression(i, i + 100) {
                    vulnerabilities.push(CompressedCalldataBombVulnerability::RecursiveDecompression {
                        description: "Recursive decompression pattern detected - exponential expansion risk".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn decompresses_calldata(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Decompression typically involves CALLDATALOAD + expansion loop
        let has_calldataload = self.bytecode[location..location + 30].iter().any(|&b| b == 0x35);
        let has_loop = self.bytecode[location..location + 30].iter().any(|&b| b == 0x57); // JUMPI
        
        has_calldataload && has_loop
    }
    
    fn has_decompression_limit(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check for size limit before decompression
        self.bytecode[start..range_end].windows(2).any(|w| {
            (w[0] == 0x10 || w[0] == 0x11) && // LT or GT
            w[1] == 0xFD // REVERT
        })
    }
    
    fn is_recursive_decompression(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Recursive pattern: loop calling itself
        let loop_count = self.bytecode[start..range_end].iter().filter(|&&b| b == 0x57).count();
        loop_count > 1 // Multiple nested loops suggest recursion
    }
}
