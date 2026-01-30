use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Agave/Aave Fork Callback Reentrancy Detector
/// 
/// Detects reentrancy vulnerabilities in Aave forks through callback mechanisms
/// during flash loans or liquidations.
/// 
/// **Historical Exploit**: Agave Protocol ($11M, March 2022)
/// **Attack Pattern**:
/// 1. Attacker initiates flash loan with malicious callback
/// 2. During callback, reenters protocol before state updates
/// 3. Exploits stale collateral/debt calculations
/// 4. Drains funds through repeated reentrancy
/// 
/// **Detection Strategy**:
/// - Identifies callback patterns (onFlashLoan, executeOperation)
/// - Detects missing reentrancy guards on callbacks
/// - Flags state updates after external calls
/// - Checks for CEI (Checks-Effects-Interactions) violations
pub struct AgaveAaveCallbackReentrancyDetector {
    bytecode: Vec<u8>,
}

impl AgaveAaveCallbackReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unguarded_flash_loan_callback() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Aave flash loan callback without reentrancy guard - Agave vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Add reentrancy guard to all flash loan callback functions".to_string(),
            });
        }

        if self.has_callback_state_update_after_call() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "State updates after callback execution - CEI violation".to_string(),
                operations: Vec::new(),
                remediation: "Move state updates before external callback execution".to_string(),
            });
        }

        if self.has_liquidation_callback_reentrancy() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Liquidation callback allows reentrancy during collateral seizure".to_string(),
                operations: Vec::new(),
                remediation: "Protect liquidation functions with reentrancy guards".to_string(),
            });
        }

        warnings
    }

    fn has_unguarded_flash_loan_callback(&self) -> bool {
        // Look for executeOperation or onFlashLoan selectors
        let execute_op_selector = [0x92, 0x0f, 0x5c, 0x84]; // executeOperation(...)
        let flash_loan_selector = [0x23, 0xe3, 0x0c, 0x8b]; // onFlashLoan(...)
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Check for callback selector
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == execute_op_selector || selector == flash_loan_selector {
                    let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                    
                    // Check for reentrancy guard (SLOAD -> ISZERO -> JUMPI pattern)
                    let has_guard = window.windows(4).any(|w| {
                        w[0] == 0x54 && // SLOAD
                        w[1] == 0x15 && // ISZERO
                        w[2] == 0x57    // JUMPI
                    });
                    
                    // Check for CALL/DELEGATECALL to user-controlled address
                    let has_external_call = window.iter().any(|&op| {
                        op == 0xf1 || op == 0xf4 // CALL or DELEGATECALL
                    });
                    
                    if has_external_call && !has_guard {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_callback_state_update_after_call(&self) -> bool {
        // Pattern: CALL/DELEGATECALL -> SSTORE (state update after external call)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL/DELEGATECALL
                // Check next 10 opcodes for SSTORE
                let window = &self.bytecode[i+1..i+10.min(self.bytecode.len())];
                
                if window.contains(&0x55) { // SSTORE after external call
                    // Verify this is not just cleaning up temporary variables
                    // Look for arithmetic or complex operations between CALL and SSTORE
                    let has_complex_logic = window.iter().any(|&op| {
                        op == 0x02 || // MUL
                        op == 0x04 || // DIV
                        op == 0x01 || // ADD
                        op == 0x03    // SUB
                    });
                    
                    if has_complex_logic {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_liquidation_callback_reentrancy(&self) -> bool {
        // Look for liquidationCall selector: 0xe8e33700
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() &&
               self.bytecode[i+1..i+5] == [0xe8, 0xe3, 0x37, 0x00]
            {
                let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                
                // Check for CALL (to seize collateral) without guard
                let has_call = window.iter().any(|&op| op == 0xf1);
                let has_guard = window.windows(3).any(|w| {
                    w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57 // SLOAD ISZERO JUMPI
                });
                
                // Check for SSTORE after CALL (updating debt/collateral)
                let mut call_pos = None;
                for (j, &op) in window.iter().enumerate() {
                    if op == 0xf1 {
                        call_pos = Some(j);
                        break;
                    }
                }
                
                if let Some(pos) = call_pos {
                    let has_sstore_after = window[pos..].contains(&0x55);
                    if has_call && !has_guard && has_sstore_after {
                        return true;
                    }
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
    fn test_agave_callback_reentrancy() {
        let vulnerable_bytecode = vec![
            0x63, 0x92, 0x0f, 0x5c, 0x84, // PUSH4 executeOperation()
            0xf4, // DELEGATECALL (callback to attacker)
            0x02, // MUL (complex calculation)
            0x55, // SSTORE (state update after call)
        ];

        let detector = AgaveAaveCallbackReentrancyDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty(), "Should detect Agave callback reentrancy");
    }

    #[test]
    fn test_safe_guarded_callback() {
        let safe_bytecode = vec![
            0x63, 0x92, 0x0f, 0x5c, 0x84, // executeOperation()
            0x54, // SLOAD (reentrancy guard)
            0x15, // ISZERO
            0x57, // JUMPI (revert if locked)
            0xf4, // DELEGATECALL
            0x55, // SSTORE
        ];

        let detector = AgaveAaveCallbackReentrancyDetector::new(safe_bytecode);
        let warnings = detector.detect();
        assert!(warnings.is_empty(), "Guarded callback should be safe");
    }
}
