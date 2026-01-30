use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PanicWithdrawDosVulnerability {
    HighGasCostExit { description: String, location: usize, confidence: f32 },
    UnboundedWithdrawalLoop { description: String, location: usize },
    GasGriefingWithdrawal { description: String, location: usize },
}

pub struct PanicWithdrawDosDetector {
    bytecode: Vec<u8>,
}

impl PanicWithdrawDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PanicWithdrawDosVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // withdraw selector: 0x3ccfd60b (common)
        let withdraw_selector = [0x3c, 0xcf, 0xd6, 0x0b];
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i..].windows(4).any(|w| w == withdraw_selector) {
                // Check for expensive operations in withdrawal
                if self.has_expensive_operations(i, i + 100) {
                    vulnerabilities.push(PanicWithdrawDosVulnerability::HighGasCostExit {
                        description: "Withdrawal function has expensive operations - gas costs prevent exit during crisis".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                // Check for unbounded loops
                if self.has_unbounded_loop(i, i + 100) {
                    vulnerabilities.push(PanicWithdrawDosVulnerability::UnboundedWithdrawalLoop {
                        description: "Withdrawal has unbounded loop - DoS during bank run".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_expensive_operations(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let window = &self.bytecode[start..range_end];
        
        // Multiple SSTOREs (expensive)
        let sstore_count = window.iter().filter(|&&b| b == 0x55).count();
        // Multiple external calls
        let call_count = window.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
        // SHA3 operations
        let sha3_count = window.iter().filter(|&&b| b == 0x20).count();
        
        sstore_count > 5 || call_count > 3 || sha3_count > 2
    }
    
    fn has_unbounded_loop(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let window = &self.bytecode[start..range_end];
        
        // JUMPI (loop) without clear bound check
        let has_jumpi = window.iter().any(|&b| b == 0x57);
        let has_gt_lt = window.iter().any(|&b| b == 0x10 || b == 0x11);
        
        // Loop exists but insufficient bounds checking
        has_jumpi && !has_gt_lt
    }
}
