use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc20ApproveRaceConditionVulnerability {
    ApproveWithoutZeroFirst { description: String, location: usize, confidence: f32 },
    NoIncreaseDecreaseAllowance { description: String, location: usize },
    DirectApproveOverwrite { description: String, location: usize },
}

pub struct Erc20ApproveRaceConditionDetector {
    bytecode: Vec<u8>,
}

impl Erc20ApproveRaceConditionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc20ApproveRaceConditionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // ERC20 approve() selector: 0x095ea7b3
        let approve_selector = [0x09, 0x5e, 0xa7, 0xb3];
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_approve_function(i) {
                // Check if approve sets allowance directly without checking current value
                if self.sets_allowance_directly(i, i + 100) {
                    if !self.has_zero_check_before_approve(i, i + 100) {
                        vulnerabilities.push(Erc20ApproveRaceConditionVulnerability::ApproveWithoutZeroFirst {
                            description: "approve() overwrites allowance without requiring current allowance to be 0 - frontrun vulnerability".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                }
                
                // Check for missing increaseAllowance/decreaseAllowance pattern
                if !self.has_increase_decrease_allowance() {
                    vulnerabilities.push(Erc20ApproveRaceConditionVulnerability::NoIncreaseDecreaseAllowance {
                        description: "Missing increaseAllowance/decreaseAllowance functions - approve() race condition risk".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_approve_function(&self, location: usize) -> bool {
        if location + 4 > self.bytecode.len() {
            return false;
        }
        
        // Look for approve selector in PUSH4
        self.bytecode[location..location + 4] == [0x09, 0x5e, 0xa7, 0xb3]
    }
    
    fn sets_allowance_directly(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Pattern: SSTORE without prior SLOAD check
        // Allowance is typically in mapping slot, so we look for:
        // - CALLDATALOAD (get spender)
        // - CALLDATALOAD (get amount)
        // - SSTORE (set allowance)
        
        let has_calldataload = self.bytecode[start..range_end].iter().filter(|&&b| b == 0x35).count() >= 2;
        let has_sstore = self.bytecode[start..range_end].iter().any(|&b| b == 0x55);
        
        has_calldataload && has_sstore
    }
    
    fn has_zero_check_before_approve(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check for pattern: SLOAD → ISZERO → JUMPI/REVERT
        // This indicates checking current allowance == 0
        let has_sload = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        let has_iszero = self.bytecode[start..range_end].iter().any(|&b| b == 0x15);
        let has_conditional = self.bytecode[start..range_end].iter().any(|&b| b == 0x57 || b == 0xFD);
        
        has_sload && has_iszero && has_conditional
    }
    
    fn has_increase_decrease_allowance(&self) -> bool {
        // increaseAllowance selector: 0x39509351
        // decreaseAllowance selector: 0xa457c2d7
        
        let increase_selector = [0x39, 0x50, 0x93, 0x51];
        let decrease_selector = [0xa4, 0x57, 0xc2, 0xd7];
        
        let has_increase = self.bytecode.windows(4).any(|w| w == increase_selector);
        let has_decrease = self.bytecode.windows(4).any(|w| w == decrease_selector);
        
        has_increase || has_decrease
    }
}
