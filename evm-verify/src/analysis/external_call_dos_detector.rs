/// External Call DoS Detector
///
/// Detects DoS vulnerabilities from external calls:
/// 1. Unchecked external call that can revert entire transaction
/// 2. External call in loop (one failure blocks all)
/// 3. Gas griefing via expensive fallback functions
///
/// Solution: Pull pattern, try-catch, or graceful failure handling

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalCallDoS {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub dos_type: DoSType,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DoSType {
    UncheckedCallRevert,      // Call failure reverts entire tx
    CallInLoop,                // One recipient can block all withdrawals
    GasGriefing,               // Expensive fallback consumes all gas
    DependencyOnExternal,      // Critical path depends on external success
}

pub struct ExternalCallDoSDetector {
    bytecode: Vec<u8>,
}

impl ExternalCallDoSDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<ExternalCallDoS> {
        let mut vulnerabilities = Vec::new();
        
        vulnerabilities.extend(self.detect_unchecked_call());
        vulnerabilities.extend(self.detect_call_in_loop());
        vulnerabilities.extend(self.detect_unlimited_gas_forward());
        vulnerabilities.extend(self.detect_critical_dependency());
        
        vulnerabilities
    }
    
    fn detect_unchecked_call(&self) -> Vec<ExternalCallDoS> {
        let mut vulns = Vec::new();
        
        // Pattern: CALL without checking return value
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.is_external_call(i) {
                let call_pc = i;
                
                // Check if return value is checked
                let return_checked = self.is_return_value_checked(call_pc);
                
                if !return_checked {
                    vulns.push(ExternalCallDoS {
                        vulnerability_type: "Unchecked External Call".to_string(),
                        severity: "High".to_string(),
                        location: call_pc,
                        description: "External call failure not checked, can revert entire transaction".to_string(),
                        dos_type: DoSType::UncheckedCallRevert,
                        exploit_scenario: 
                            "Withdraw function sends ETH to users:\n\
                             1. One user has reverting fallback\n\
                             2. Call to that user fails\n\
                             3. Entire withdraw transaction reverts\n\
                             4. No one can withdraw (DoS)".to_string(),
                        remediation: 
                            "Check return value: (bool success, ) = addr.call{value: amount}(\"\");\n\
                             Or use try-catch for graceful failure".to_string(),
                    });
                }
            }
        }
        
        vulns
    }
    
    fn detect_call_in_loop(&self) -> Vec<ExternalCallDoS> {
        let mut vulns = Vec::new();
        
        // Pattern: External call inside loop
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_external_call(i) {
                if self.is_in_loop(i) {
                    vulns.push(ExternalCallDoS {
                        vulnerability_type: "External Call in Loop".to_string(),
                        severity: "Critical".to_string(),
                        location: i,
                        description: "External call inside loop - single failure blocks all iterations".to_string(),
                        dos_type: DoSType::CallInLoop,
                        exploit_scenario: 
                            "Airdrop contract sends tokens to list of recipients:\n\
                             1. Attacker includes address with reverting receive()\n\
                             2. Loop reaches attacker's address and reverts\n\
                             3. Entire airdrop fails, no one gets tokens\n\
                             4. Contract funds locked".to_string(),
                        remediation: 
                            "Use pull pattern instead of push:\n\
                             mapping(address => uint) public balances;\n\
                             function claim() { transfer(balances[msg.sender]); }".to_string(),
                    });
                }
            }
        }
        
        vulns
    }
    
    fn detect_unlimited_gas_forward(&self) -> Vec<ExternalCallDoS> {
        let mut vulns = Vec::new();
        
        // Pattern: CALL with unlimited gas (forwards all available gas)
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xF1 { // CALL
                // Check if gas parameter is GAS opcode (forwards all gas)
                let forwards_all_gas = self.bytecode[i.saturating_sub(15)..i]
                    .iter()
                    .any(|&op| op == 0x5A); // GAS opcode
                
                if forwards_all_gas {
                    vulns.push(ExternalCallDoS {
                        vulnerability_type: "Unlimited Gas Forwarding".to_string(),
                        severity: "Medium".to_string(),
                        location: i,
                        description: "External call forwards all available gas".to_string(),
                        dos_type: DoSType::GasGriefing,
                        exploit_scenario: 
                            "Attacker's fallback function:\n\
                             1. Consumes all forwarded gas\n\
                             2. No gas left for subsequent operations\n\
                             3. Transaction fails or becomes very expensive".to_string(),
                        remediation: "Limit gas: addr.call{gas: 2300}(\"\") or use fixed gas amount".to_string(),
                    });
                }
            }
        }
        
        vulns
    }
    
    fn detect_critical_dependency(&self) -> Vec<ExternalCallDoS> {
        let mut vulns = Vec::new();
        
        // Pattern: External call followed by critical operation without failure handling
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.is_external_call(i) {
                // Check if followed by critical operations (SSTORE, transfer, etc)
                let end = (i + 20).min(self.bytecode.len());
                let has_critical_ops = if end > i + 1 {
                    self.bytecode[i+1..end]
                        .iter()
                        .any(|&op| op == 0x55 || op == 0xF1) // SSTORE or another CALL
                } else {
                    false
                };
                
                let no_failure_handling = !self.has_jumpi_after(i);
                
                if has_critical_ops && no_failure_handling {
                    vulns.push(ExternalCallDoS {
                        vulnerability_type: "Critical Dependency on External Call".to_string(),
                        severity: "High".to_string(),
                        location: i,
                        description: "Critical operations depend on external call success without fallback".to_string(),
                        dos_type: DoSType::DependencyOnExternal,
                        exploit_scenario: "External service failure permanently bricks contract functionality".to_string(),
                        remediation: "Add fallback logic: if (!success) { handleFailure(); }".to_string(),
                    });
                }
            }
        }
        
        vulns
    }
    
    fn is_external_call(&self, pc: usize) -> bool {
        matches!(self.bytecode.get(pc), Some(&0xF1) | Some(&0xF4)) // CALL or DELEGATECALL
    }
    
    fn is_return_value_checked(&self, call_pc: usize) -> bool {
        // Check if call result is used in conditional jump (ISZERO + JUMPI)
        for i in call_pc+1..call_pc+10.min(self.bytecode.len()) {
            if self.bytecode[i] == 0x15 { // ISZERO (checking if call failed)
                if i+1 < self.bytecode.len() && self.bytecode[i+1] == 0x57 { // JUMPI
                    return true;
                }
            }
        }
        false
    }
    
    fn is_in_loop(&self, pc: usize) -> bool {
        let has_jumpdest_before = self.bytecode[pc.saturating_sub(50)..pc]
            .iter()
            .any(|&op| op == 0x5B);
        
        let end = (pc + 50).min(self.bytecode.len());
        let has_backward_jump = if end > pc {
            self.bytecode[pc..end]
                .iter()
                .any(|&op| op == 0x56 || op == 0x57)
        } else {
            false
        };
        
        has_jumpdest_before && has_backward_jump
    }
    
    fn has_jumpi_after(&self, pc: usize) -> bool {
        let end = (pc + 15).min(self.bytecode.len());
        if end > pc {
            self.bytecode[pc..end]
                .iter()
                .any(|&op| op == 0x57) // JUMPI (conditional branch)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unchecked_call() {
        let bytecode = vec![
            0xF1,              // CALL (external)
            0x55,              // SSTORE (continues without checking)
        ];
        
        let detector = ExternalCallDoSDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.len() > 0);
    }
    
    #[test]
    fn test_safe_checked_call() {
        let bytecode = vec![
            0xF1,              // CALL
            0x15,              // ISZERO (check if failed)
            0x57,              // JUMPI (handle failure)
            0x55,              // SSTORE (only if success)
        ];
        
        let detector = ExternalCallDoSDetector::new(bytecode);
        let vulns = detector.detect_unchecked_call();
        
        assert_eq!(vulns.len(), 0); // Safe - checks return value
    }
}
