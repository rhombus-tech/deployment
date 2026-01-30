use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Withdrawal Queue Manipulation Detector (Jones DAO/Epoch-based)
/// 
/// Detects vulnerabilities in epoch-based withdrawal queues where queue positioning
/// or timing can be gamed for unfair advantage or denial-of-service.
/// 
/// **Attack Patterns**:
/// 1. First-in-line attacks to monopolize withdrawals
/// 2. Queue DOS by submitting dust requests
/// 3. Epoch boundary gaming for preferential treatment
/// 4. Queue front-running for best pricing
/// 5. Withdrawal request cancellation abuse
/// 
/// **Detection Strategy**:
/// - Identifies queue insertion without anti-spam measures
/// - Detects missing queue position fairness mechanisms
/// - Flags epoch transitions without protection
/// - Checks for withdrawal timing manipulation
/// - Validates queue size limits
pub struct WithdrawalQueueManipulationDetector {
    bytecode: Vec<u8>,
}

impl WithdrawalQueueManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_queue_spam_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Withdrawal queue vulnerable to spam/DOS with dust requests".to_string(),
                operations: Vec::new(),
                remediation: "Add minimum withdrawal amount and queue request limits per address".to_string(),
            });
        }

        if self.has_first_in_line_monopolization() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "First users can monopolize withdrawal queue unfairly".to_string(),
                operations: Vec::new(),
                remediation: "Implement pro-rata withdrawals or randomized queue ordering".to_string(),
            });
        }

        if self.has_epoch_boundary_gaming() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Epoch transitions can be gamed for preferential queue treatment".to_string(),
                operations: Vec::new(),
                remediation: "Add epoch transition buffer and prevent last-block manipulation".to_string(),
            });
        }

        if self.has_cancellation_abuse_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Withdrawal request cancellation can be abused to game queue".to_string(),
                operations: Vec::new(),
                remediation: "Add cancellation penalties or cooldowns to prevent gaming".to_string(),
            });
        }

        warnings
    }

    fn has_queue_spam_vulnerability(&self) -> bool {
        // Pattern: requestWithdrawal() without minimum amount
        let request_selector = [0x9e, 0xe6, 0x79, 0xcb]; // requestWithdrawal()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == request_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for queue addition
                    let adds_to_queue = window.contains(&0x55); // SSTORE
                    
                    // Check for minimum amount validation
                    let has_min_amount = window.windows(8).any(|w| {
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (min amount)
                        w.iter().any(|&op| op == 0x11) && // GT
                        w.iter().any(|&op| op == 0xfd) // REVERT if too small
                    });
                    
                    // Check for per-user request limit
                    let has_user_limit = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (user requests)
                        w.iter().any(|&op| op == 0x54) && // SLOAD (count)
                        w.iter().any(|&op| op == 0x11) // GT (check limit)
                    });
                    
                    if adds_to_queue && !has_min_amount && !has_user_limit {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_first_in_line_monopolization(&self) -> bool {
        // Pattern: FIFO queue processing without fairness
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for queue processing loop
            if self.bytecode[i] == 0x56 { // JUMP (queue iteration)
                let window = &self.bytecode[i.saturating_sub(35)..i+10.min(self.bytecode.len())];
                
                // Check for queue iteration
                let iterates_queue = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x54) && // SLOAD (queue item)
                    w.iter().any(|&op| op == 0x01) // ADD (increment index)
                });
                
                // Check for pro-rata distribution
                let uses_pro_rata = window.windows(12).any(|w| {
                    // Each user gets proportional share
                    w.iter().any(|&op| op == 0x02) && // MUL (user_amount * available)
                    w.iter().any(|&op| op == 0x04) // DIV (/ total_requested)
                });
                
                // Check for randomization
                let randomizes_order = window.iter().any(|&op| {
                    op == 0x40 || op == 0x44 // BLOCKHASH or PREVRANDAO
                });
                
                if iterates_queue && !uses_pro_rata && !randomizes_order {
                    return true;
                }
            }
        }
        false
    }

    fn has_epoch_boundary_gaming(&self) -> bool {
        // Pattern: epoch transition without protection
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for epoch check
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                
                // Check for epoch calculation
                let calculates_epoch = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x04) && // DIV (timestamp / epoch_duration)
                    w.iter().any(|&op| op == 0x54) // SLOAD (current epoch)
                });
                
                if calculates_epoch {
                    // Check for transition buffer
                    let has_buffer = window.windows(12).any(|w| {
                        // Prevent requests in last X blocks of epoch
                        w.iter().any(|&op| op == 0x03) && // SUB (epoch_end - buffer)
                        w.iter().any(|&op| op == 0x10) // LT (check if in buffer)
                    });
                    
                    // Check for request locking
                    let locks_requests = window.windows(10).any(|w| {
                        // Lock withdrawals during transition
                        w.iter().any(|&op| op == 0x55) && // SSTORE (lock flag)
                        w.iter().any(|&op| op == 0x43) // NUMBER (block-based lock)
                    });
                    
                    if !has_buffer && !locks_requests {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_cancellation_abuse_risk(&self) -> bool {
        // Pattern: cancelWithdrawal() without penalty
        let cancel_selector = [0x3e, 0x3b, 0x5b, 0x19]; // cancelWithdrawal()
        
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == cancel_selector {
                    let window = &self.bytecode[i..i+45.min(self.bytecode.len())];
                    
                    // Check for queue removal
                    let removes_from_queue = window.contains(&0x55); // SSTORE
                    
                    // Check for cancellation penalty/fee
                    let has_penalty = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x02) && // MUL (amount * fee)
                        w.iter().any(|&op| op == 0x04) // DIV (calculate penalty)
                    });
                    
                    // Check for cooldown after cancellation
                    let has_cooldown = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x55) // SSTORE (last cancel time)
                    });
                    
                    if removes_from_queue && !has_penalty && !has_cooldown {
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
    fn test_queue_spam() {
        let vulnerable_bytecode = vec![
            0x63, 0x9e, 0xe6, 0x79, 0xcb, // requestWithdrawal()
            0x55, // SSTORE (add to queue - no minimum!)
        ];

        let detector = WithdrawalQueueManipulationDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("queue") || w.description.contains("spam")));
    }
}
