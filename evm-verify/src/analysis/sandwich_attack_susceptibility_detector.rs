use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SandwichAttackSusceptibilityVulnerability {
    NoSlippageProtection { description: String, location: usize, confidence: f32 },
    PublicMempoolExposure { description: String, location: usize },
    NoDeadlineCheck { description: String, location: usize },
}

pub struct SandwichAttackSusceptibilityDetector {
    bytecode: Vec<u8>,
}

impl SandwichAttackSusceptibilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SandwichAttackSusceptibilityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Uniswap swapExactTokensForTokens: 0x38ed1739
        let swap_selector = [0x38, 0xed, 0x17, 0x39];
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i..].windows(4).any(|w| w == swap_selector) {
                if !self.has_slippage_check(i, i + 80) {
                    vulnerabilities.push(SandwichAttackSusceptibilityVulnerability::NoSlippageProtection {
                        description: "Swap without slippage protection - vulnerable to sandwich attacks".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
                
                if !self.has_deadline_check(i, i + 80) {
                    vulnerabilities.push(SandwichAttackSusceptibilityVulnerability::NoDeadlineCheck {
                        description: "Swap without deadline - can be delayed and sandwiched".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_slippage_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Slippage check: amountOutMin parameter validation
        // Look for: LT/GT comparison + REVERT
        self.bytecode[start..range_end].windows(3).any(|w| {
            (w[0] == 0x10 || w[0] == 0x11) && w[2] == 0xFD
        })
    }
    
    fn has_deadline_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Deadline check uses TIMESTAMP
        self.bytecode[start..range_end].iter().any(|&b| b == 0x42)
    }
}
