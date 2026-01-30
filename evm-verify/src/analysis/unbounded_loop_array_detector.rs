use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnboundedLoopArrayVulnerability {
    ArrayLengthNotBounded { description: String, location: usize, confidence: f32 },
    DynamicArrayIteration { description: String, location: usize },
    UserControlledArraySize { description: String, location: usize },
}

pub struct UnboundedLoopArrayDetector {
    bytecode: Vec<u8>,
}

impl UnboundedLoopArrayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UnboundedLoopArrayVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.iterates_over_array(i, i + 120) {
                if !self.validates_array_length(i, i + 120) {
                    vulnerabilities.push(UnboundedLoopArrayVulnerability::ArrayLengthNotBounded {
                        description: "Iterates over array without length check - unbounded DoS".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
                
                if self.array_size_from_calldata(i, i + 120) {
                    vulnerabilities.push(UnboundedLoopArrayVulnerability::UserControlledArraySize {
                        description: "Loop bound controlled by user input without validation".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn iterates_over_array(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Pattern: array.length access + loop
        let has_mload = self.bytecode[start..range_end].iter().any(|&b| b == 0x51);
        let has_loop = self.bytecode[start..range_end].iter().any(|&b| b == 0x57);
        
        has_mload && has_loop
    }
    
    fn validates_array_length(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check for max length comparison
        self.bytecode[start..range_end]
            .windows(3)
            .any(|w| (w[0] == 0x10 || w[0] == 0x11) && w[2] == 0xFD)
    }
    
    fn array_size_from_calldata(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // CALLDATALOAD used for loop bound
        self.bytecode[start..range_end].iter().any(|&b| b == 0x35)
    }
}
