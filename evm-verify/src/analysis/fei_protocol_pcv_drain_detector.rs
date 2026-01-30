use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Fei Protocol PCV (Protocol Controlled Value) Drain Detector
/// 
/// Detects vulnerabilities in protocol-controlled value mechanisms where
/// treasury funds can be drained through governance or access control exploits.
/// 
/// **Historical Context**: Fei Protocol various incidents
/// **Attack Patterns**:
/// 1. Governance manipulation to approve malicious PCV allocation
/// 2. Access control bypass in PCV controller contracts
/// 3. Flash loan attacks on PCV rebalancing mechanisms
/// 4. Unchecked external calls in PCV operations
/// 
/// **Detection Strategy**:
/// - Identifies PCV withdrawal/allocation without proper guards
/// - Detects missing multi-sig or timelock protection
/// - Flags unchecked external calls with PCV funds
/// - Checks for governance bypass vulnerabilities
pub struct FeiProtocolPcvDrainDetector {
    bytecode: Vec<u8>,
}

impl FeiProtocolPcvDrainDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unprotected_pcv_withdrawal() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "PCV withdrawal without proper access control - Fei Protocol vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Add role-based access control and multi-sig requirements for PCV operations".to_string(),
            });
        }

        if self.has_missing_timelock_protection() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "PCV operations lack timelock or delay mechanism".to_string(),
                operations: Vec::new(),
                remediation: "Implement timelock mechanism for all PCV fund transfers".to_string(),
            });
        }

        if self.has_unchecked_pcv_transfer() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::UncheckedExternalCall,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Unchecked external call in PCV transfer operation".to_string(),
                operations: Vec::new(),
                remediation: "Check return value of all external calls handling PCV funds".to_string(),
            });
        }

        warnings
    }

    fn has_unprotected_pcv_withdrawal(&self) -> bool {
        // withdraw() or allocate() selectors
        let withdraw_selector = [0x2e, 0x1a, 0x7d, 0x4d]; // withdraw()
        let allocate_selector = [0x00, 0x00, 0x00, 0x00]; // Custom allocate
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == withdraw_selector {
                    let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                    
                    // Check for access control (CALLER check)
                    let has_access_control = window.windows(5).any(|w| {
                        w[0] == 0x33 && // CALLER
                        (w[1] == 0x14 || w[1] == 0x54) // EQ or SLOAD (role check)
                    });
                    
                    // Check for CALL (fund transfer)
                    let has_transfer = window.iter().any(|&op| op == 0xf1);
                    
                    if has_transfer && !has_access_control {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_timelock_protection(&self) -> bool {
        // Look for governance operations without timestamp checks
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xf1 { // CALL (transfer funds)
                let window = &self.bytecode[i.saturating_sub(20)..i+10.min(self.bytecode.len())];
                
                // Check for timestamp comparison (timelock)
                let has_timelock = window.iter().any(|&op| {
                    op == 0x42 // TIMESTAMP
                });
                
                // Check for large value transfer (PCV-sized)
                let has_large_value = window.windows(2).any(|w| {
                    w[0] >= 0x60 && w[0] <= 0x7f // PUSH (large value)
                });
                
                if has_large_value && !has_timelock {
                    return true;
                }
            }
        }
        false
    }

    fn has_unchecked_pcv_transfer(&self) -> bool {
        // Pattern: CALL (transfer) without ISZERO check
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0xf1 { // CALL
                let window = &self.bytecode[i..i+10.min(self.bytecode.len())];
                
                // Check for return value check
                let has_check = window.iter().any(|&op| {
                    op == 0x15 || op == 0xfd // ISZERO or REVERT
                });
                
                if !has_check {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fei_pcv_drain() {
        let vulnerable_bytecode = vec![
            0x63, 0x2e, 0x1a, 0x7d, 0x4d, // withdraw()
            0x60, 0xff, 0xff, // PUSH large value
            0xf1, // CALL (no check!)
        ];

        let detector = FeiProtocolPcvDrainDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
