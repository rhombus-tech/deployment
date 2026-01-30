use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockGasLimitDosVulnerability {
    UnboundedArrayIteration { description: String, location: usize, confidence: f32 },
    GasIntensiveLoop { description: String, location: usize },
    NoGasCheckInLoop { description: String, location: usize },
}

pub struct BlockGasLimitDosDetector {
    bytecode: Vec<u8>,
}

impl BlockGasLimitDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BlockGasLimitDosVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_loop_start(i) {
                if self.has_unbounded_iteration(i, i + 100) {
                    vulnerabilities.push(BlockGasLimitDosVulnerability::UnboundedArrayIteration {
                        description: "Unbounded loop over user-controlled array - can hit block gas limit".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                if self.has_expensive_operations_in_loop(i, i + 100) {
                    vulnerabilities.push(BlockGasLimitDosVulnerability::GasIntensiveLoop {
                        description: "Loop contains SSTORE or external calls - DoS risk".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_loop_start(&self, location: usize) -> bool {
        if location + 10 > self.bytecode.len() {
            return false;
        }
        
        // JUMPDEST followed by loop pattern
        self.bytecode[location] == 0x5B
    }
    
    fn has_unbounded_iteration(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Loop without max iterations check
        let has_jumpi = self.bytecode[start..range_end].iter().any(|&b| b == 0x57);
        let has_limit_check = self.bytecode[start..range_end]
            .windows(2)
            .any(|w| (w[0] == 0x10 || w[0] == 0x11) && w[1] == 0xFD);
        
        has_jumpi && !has_limit_check
    }
    
    fn has_expensive_operations_in_loop(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // SSTORE or external calls in loop
        self.bytecode[start..range_end].iter().any(|&b| {
            b == 0x55 || // SSTORE
            b == 0xF1 || // CALL
            b == 0xFA    // STATICCALL
        })
    }
}
