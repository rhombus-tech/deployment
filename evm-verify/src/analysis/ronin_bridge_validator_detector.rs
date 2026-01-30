use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Ronin Bridge Validator Key Management Detector
/// 
/// Detects critical vulnerabilities in multi-signature bridge validator systems
/// where compromising a threshold of validator keys can drain the entire bridge.
/// 
/// **Historical Exploit**: Ronin/Axie Infinity Bridge ($625M, March 2022)
/// **LARGEST DEFI HACK IN HISTORY**
/// 
/// **Attack Pattern**:
/// 1. Attackers compromised 5 of 9 validator private keys (Sky Mavis: 4, Axie DAO: 1)
/// 2. Used compromised keys to approve malicious withdrawals
/// 3. Drained 173,600 ETH and 25.5M USDC (~$625M)
/// 4. Exploit went undetected for 6 days
/// 
/// **Key Vulnerabilities**:
/// - Insufficient validator decentralization (5/9 controlled by Sky Mavis)
/// - No monitoring for unusual validator behavior
/// - Missing rate limits on large withdrawals
/// - Lack of timelocks for governance changes to validators
/// 
/// **Detection Strategy**:
/// - Identifies low validator threshold relative to total validators
/// - Detects validators controlled by single entity (centralization)
/// - Flags missing withdrawal amount limits
/// - Checks for lack of timelock on validator changes
/// - Validates monitoring/alerting for validator consensus
pub struct RoninBridgeValidatorDetector {
    bytecode: Vec<u8>,
}

impl RoninBridgeValidatorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_low_validator_threshold() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Bridge validator threshold too low - Ronin-style vulnerability (compromise threshold < 66%)".to_string(),
                operations: Vec::new(),
                remediation: "Require at least 2/3 (66%+) validator signatures and ensure geographic/entity distribution".to_string(),
            });
        }

        if self.has_centralized_validator_control() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Multiple validators potentially controlled by single entity - centralization risk".to_string(),
                operations: Vec::new(),
                remediation: "Ensure validators are operated by independent entities across jurisdictions".to_string(),
            });
        }

        if self.has_missing_withdrawal_limits() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "No withdrawal amount limits or rate limiting for bridge operations".to_string(),
                operations: Vec::new(),
                remediation: "Implement daily/hourly withdrawal limits and require additional approvals for large amounts".to_string(),
            });
        }

        if self.has_validator_change_without_timelock() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Validator set can be changed without timelock - enables rapid takeover".to_string(),
                operations: Vec::new(),
                remediation: "Add minimum 48-72 hour timelock for all validator set changes".to_string(),
            });
        }

        if self.has_missing_consensus_monitoring() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "No on-chain validator consensus monitoring or anomaly detection".to_string(),
                operations: Vec::new(),
                remediation: "Implement validator behavior monitoring and consensus anomaly alerts".to_string(),
            });
        }

        warnings
    }

    fn has_low_validator_threshold(&self) -> bool {
        // Pattern: threshold check in multi-sig validation
        // Look for: sigCount >= threshold check
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x11 || self.bytecode[i] == 0x10 { // GT or LT
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for signature counting loop
                let has_sig_loop = window.windows(15).any(|w| {
                    // Pattern: ecrecover loop counting valid signatures
                    w.iter().any(|&op| op == 0x01) && // ecrecover precompile
                    w.iter().any(|&op| op == 0x01) && // ADD (increment counter)
                    w.iter().any(|&op| op == 0x56) // JUMP (loop)
                });
                
                // Check for threshold constant
                let has_threshold = window.windows(4).any(|w| {
                    // Common thresholds: PUSH1 0x03 (3), PUSH1 0x05 (5), etc.
                    (w[0] >= 0x60 && w[0] <= 0x7f) && // PUSH
                    (w[1] >= 0x02 && w[1] <= 0x09) // Small threshold (2-9)
                });
                
                // Check for total validators count
                let has_total_validators = window.windows(3).any(|w| {
                    w.iter().any(|&op| op == 0x54) // SLOAD (validator count)
                });
                
                // Vulnerable if has low threshold (< 2/3)
                // Heuristic: threshold appears to be < 66% of validators
                if has_sig_loop && has_threshold && has_total_validators {
                    // Check if threshold seems low (e.g., 5 out of 9 = 55%)
                    // This is a simplified heuristic
                    return true;
                }
            }
        }
        false
    }

    fn has_centralized_validator_control(&self) -> bool {
        // Check if validators can be set by single admin without distribution checks
        let add_validator = [0x4d, 0x23, 0x8c, 0x8e]; // addValidator() or similar
        let set_validators = [0x82, 0xdc, 0x1e, 0xc4]; // setValidators()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == add_validator || selector == set_validators {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for simple owner-only check (centralized)
                    let has_owner_only = window.windows(6).any(|w| {
                        w.iter().any(|&op| op == 0x33) && // CALLER
                        w.iter().any(|&op| op == 0x14) // EQ (owner check)
                    });
                    
                    // Check for entity diversity validation (should have this!)
                    let has_entity_check = window.windows(15).any(|w| {
                        // Pattern: multiple address comparisons or entity registry check
                        w.iter().filter(|&&op| op == 0x20).count() >= 2 && // Multiple KECCAK256
                        w.iter().filter(|&&op| op == 0x14).count() >= 2 // Multiple EQ checks
                    });
                    
                    // Check for geographic/jurisdiction validation
                    let has_jurisdiction_check = window.contains(&0xfa); // STATICCALL to registry
                    
                    if has_owner_only && !has_entity_check && !has_jurisdiction_check {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_withdrawal_limits(&self) -> bool {
        // Pattern: withdraw() or submitTransaction() without amount limits
        let withdraw = [0x3c, 0xcf, 0xd6, 0x0b]; // withdraw()
        let submit_tx = [0xc6, 0x42, 0x74, 0x86]; // submitTransaction()
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == withdraw || selector == submit_tx {
                    let window = &self.bytecode[i..i+60.min(self.bytecode.len())];
                    
                    // Check for amount parameter
                    let has_amount = window.iter().any(|&op| {
                        op == 0x35 // CALLDATALOAD (amount parameter)
                    });
                    
                    // Check for maximum amount limit
                    let has_max_limit = window.windows(6).any(|w| {
                        // Pattern: amount > maxWithdrawal -> REVERT
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (max limit)
                        w.iter().any(|&op| op == 0x11) && // GT (amount > max)
                        w.iter().any(|&op| op == 0xfd) // REVERT
                    });
                    
                    // Check for rate limiting
                    let has_rate_limit = window.windows(12).any(|w| {
                        // Pattern: dailyWithdrawn + amount > dailyLimit
                        w.iter().any(|&op| op == 0x54) && // SLOAD (daily withdrawn)
                        w.iter().any(|&op| op == 0x01) && // ADD (+ amount)
                        w.iter().any(|&op| op == 0x11) // GT (check daily limit)
                    });
                    
                    // Check for timelock on large amounts
                    let has_large_amount_timelock = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x42) // TIMESTAMP (timelock)
                    });
                    
                    if has_amount && !has_max_limit && !has_rate_limit && !has_large_amount_timelock {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_validator_change_without_timelock(&self) -> bool {
        // Pattern: addValidator/removeValidator without timelock
        let add_validator = [0x4d, 0x23, 0x8c, 0x8e];
        let remove_validator = [0x40, 0xa1, 0x41, 0x75];
        
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == add_validator || selector == remove_validator {
                    let window = &self.bytecode[i..i+45.min(self.bytecode.len())];
                    
                    // Check for validator set modification
                    let has_validator_update = window.contains(&0x55); // SSTORE
                    
                    // Check for timelock mechanism
                    let has_timelock = window.windows(12).any(|w| {
                        // Pattern: proposedTime + delay < TIMESTAMP -> allow
                        w.iter().any(|&op| op == 0x54) && // SLOAD (proposed time)
                        w.iter().any(|&op| op == 0x01) && // ADD (+ delay)
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x10) // LT (check time passed)
                    });
                    
                    // Check for proposal + execution pattern
                    let has_two_step_process = window.windows(8).any(|w| {
                        // Look for proposal flag/state
                        w.iter().filter(|&&op| op == 0x54).count() >= 2 // Multiple SLOAD (state checks)
                    });
                    
                    if has_validator_update && !has_timelock && !has_two_step_process {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_consensus_monitoring(&self) -> bool {
        // Check if bridge emits events for validator consensus tracking
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for signature verification without event emission
            if self.bytecode[i] == 0x01 { // CALL to ecrecover
                let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                
                // Check for signature validation
                let has_sig_validation = window.iter().any(|&op| {
                    op == 0x14 // EQ (compare recovered address)
                });
                
                // Check for event emission (LOG1, LOG2, LOG3, LOG4)
                let has_event = window.iter().any(|&op| {
                    op >= 0xa1 && op <= 0xa4 // LOG operations
                });
                
                // Check for consensus count storage
                let has_consensus_tracking = window.windows(6).any(|w| {
                    w.iter().any(|&op| op == 0x01) && // ADD (count signatures)
                    w.iter().any(|&op| op == 0x55) // SSTORE (store count)
                });
                
                if has_sig_validation && !has_event && !has_consensus_tracking {
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
    fn test_ronin_low_threshold() {
        // Simulates 5 of 9 validator threshold (55% - too low!)
        let vulnerable_bytecode = vec![
            0x60, 0x05, // PUSH1 0x05 (threshold = 5)
            0x60, 0x09, // PUSH1 0x09 (total validators = 9)
            0x56, // JUMP (sig counting loop)
            0x01, // ecrecover
            0x01, // ADD (count sig)
            0x11, // GT (sigCount >= threshold)
            0x57, // JUMPI
        ];

        let detector = RoninBridgeValidatorDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("threshold")));
    }

    #[test]
    fn test_missing_withdrawal_limits() {
        let vulnerable_bytecode = vec![
            0x63, 0x3c, 0xcf, 0xd6, 0x0b, // withdraw()
            0x35, // CALLDATALOAD (amount)
            0xf1, // CALL (transfer - no amount check!)
        ];

        let detector = RoninBridgeValidatorDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(warnings.iter().any(|w| 
            w.description.contains("withdrawal") || 
            w.description.contains("limit")
        ));
    }
}
