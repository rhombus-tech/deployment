/// Token Approval Race Condition Detector
/// 
/// ERC20 approve() has a known race condition:
/// 1. Alice approves Bob for 100 tokens
/// 2. Alice changes approval to 50 tokens
/// 3. Bob front-runs step 2 and spends 100 tokens
/// 4. After step 2, Bob can spend another 50 tokens (150 total!)
///
/// Solution: Use increaseAllowance/decreaseAllowance or approve(0) first

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenApprovalRace {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub vulnerable_function: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct TokenApprovalRaceDetector {
    bytecode: Vec<u8>,
}

impl TokenApprovalRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<TokenApprovalRace> {
        let mut vulnerabilities = Vec::new();
        
        // Check if contract has ERC20 approve function
        if !self.has_approve_function() {
            return vulnerabilities;
        }
        
        vulnerabilities.extend(self.detect_unsafe_approve());
        vulnerabilities.extend(self.detect_missing_safe_approve_pattern());
        
        vulnerabilities
    }
    
    fn has_approve_function(&self) -> bool {
        // ERC20 approve(address,uint256) selector: 0x095ea7b3
        let approve_selector = [0x09, 0x5e, 0xa7, 0xb3];
        self.bytecode.windows(4).any(|w| w == approve_selector)
    }
    
    fn detect_unsafe_approve(&self) -> Vec<TokenApprovalRace> {
        let mut vulns = Vec::new();
        
        // Find approve() function implementation
        let approve_selector = [0x09, 0x5e, 0xa7, 0xb3];
        
        for i in 0..self.bytecode.len().saturating_sub(4) {
            if &self.bytecode[i..i+4] == &approve_selector {
                // Found approve selector, check implementation
                let func_start = i;
                
                // Check if approve directly sets allowance without checking current value
                let has_direct_set = self.has_direct_allowance_set(func_start, 200);
                let has_zero_check = self.has_current_allowance_check(func_start, 200);
                
                if has_direct_set && !has_zero_check {
                    vulns.push(TokenApprovalRace {
                        vulnerability_type: "ERC20 Approve Race Condition".to_string(),
                        severity: "Medium".to_string(),
                        location: func_start,
                        description: "approve() function vulnerable to front-running attack".to_string(),
                        vulnerable_function: "approve(address spender, uint256 amount)".to_string(),
                        exploit_scenario: 
                            "1. User approves spender for X tokens\n\
                             2. User changes approval to Y tokens\n\
                             3. Spender front-runs step 2, spends X tokens\n\
                             4. After step 2, spender can spend Y more tokens (X+Y total)".to_string(),
                        remediation: 
                            "Use OpenZeppelin's increaseAllowance/decreaseAllowance or require current allowance to be 0 before changing".to_string(),
                    });
                }
            }
        }
        
        vulns
    }
    
    fn detect_missing_safe_approve_pattern(&self) -> Vec<TokenApprovalRace> {
        let mut vulns = Vec::new();
        
        // Check if contract has approve() but not increaseAllowance/decreaseAllowance
        let has_approve = self.has_approve_function();
        let has_increase = self.has_increase_allowance();
        let has_decrease = self.has_decrease_allowance();
        
        if has_approve && (!has_increase || !has_decrease) {
            vulns.push(TokenApprovalRace {
                vulnerability_type: "Missing Safe Approval Functions".to_string(),
                severity: "Low".to_string(),
                location: 0,
                description: "Contract has approve() but missing safe alternatives".to_string(),
                vulnerable_function: "approve()".to_string(),
                exploit_scenario: "Users must use potentially vulnerable approve() instead of safe increaseAllowance/decreaseAllowance".to_string(),
                remediation: "Implement increaseAllowance and decreaseAllowance functions per ERC20 best practices".to_string(),
            });
        }
        
        vulns
    }
    
    fn has_direct_allowance_set(&self, start: usize, length: usize) -> bool {
        // Check if function directly stores allowance (SSTORE) without checking current value
        let end = (start + length).min(self.bytecode.len());
        
        // Look for SSTORE without preceding SLOAD comparison
        for i in start..end.saturating_sub(5) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if there's an SLOAD before this
                let has_prior_sload = self.bytecode[start..i]
                    .iter()
                    .any(|&op| op == 0x54);
                
                if !has_prior_sload {
                    return true; // Direct set without checking current value
                }
            }
        }
        
        false
    }
    
    fn has_current_allowance_check(&self, start: usize, length: usize) -> bool {
        // Pattern: SLOAD (current allowance) -> ISZERO -> JUMPI (revert if not zero)
        // This is the safe pattern: require(allowance == 0) before changing
        
        let end = (start + length).min(self.bytecode.len());
        
        for i in start..end.saturating_sub(10) {
            if self.bytecode[i] == 0x54 { // SLOAD (load current allowance)
                // Look for comparison pattern
                for j in i+1..i+6.min(end) {
                    if self.bytecode[j] == 0x15 { // ISZERO
                        if j+1 < end && self.bytecode[j+1] == 0x57 { // JUMPI
                            return true; // Has check for zero allowance
                        }
                    }
                    if self.bytecode[j] == 0x14 { // EQ
                        if j+1 < end && self.bytecode[j+1] == 0x57 { // JUMPI  
                            return true; // Has comparison check
                        }
                    }
                }
            }
        }
        
        false
    }
    
    fn has_increase_allowance(&self) -> bool {
        // increaseAllowance(address,uint256) selector: 0x39509351
        let selector = [0x39, 0x50, 0x93, 0x51];
        self.bytecode.windows(4).any(|w| w == selector)
    }
    
    fn has_decrease_allowance(&self) -> bool {
        // decreaseAllowance(address,uint256) selector: 0xa457c2d7
        let selector = [0xa4, 0x57, 0xc2, 0xd7];
        self.bytecode.windows(4).any(|w| w == selector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unsafe_approve_detection() {
        // Unsafe approve: direct SSTORE without checking current allowance
        let bytecode = vec![
            0x09, 0x5e, 0xa7, 0xb3, // approve selector
            0x60, 0x00,              // PUSH1 0
            0x55,                    // SSTORE (direct set - VULNERABLE)
        ];
        
        let detector = TokenApprovalRaceDetector::new(bytecode);
        let vulns = detector.detect_unsafe_approve();
        
        assert!(vulns.len() > 0);
    }
    
    #[test]
    fn test_safe_approve_with_zero_check() {
        // Safe approve: checks current allowance is zero first
        let bytecode = vec![
            0x09, 0x5e, 0xa7, 0xb3, // approve selector
            0x54,                    // SLOAD (load current allowance)
            0x15,                    // ISZERO
            0x57,                    // JUMPI (revert if not zero)
            0x55,                    // SSTORE (safe to set)
        ];
        
        let detector = TokenApprovalRaceDetector::new(bytecode);
        let vulns = detector.detect_unsafe_approve();
        
        assert_eq!(vulns.len(), 0); // Should be safe
    }
    
    #[test]
    fn test_missing_safe_functions() {
        // Has approve but missing increaseAllowance/decreaseAllowance
        let bytecode = vec![
            0x09, 0x5e, 0xa7, 0xb3, // approve selector only
        ];
        
        let detector = TokenApprovalRaceDetector::new(bytecode);
        let vulns = detector.detect_missing_safe_approve_pattern();
        
        assert!(vulns.len() > 0);
    }
}
