use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Gnosis Chain AMB (Arbitrary Message Bridge) Exploit Detector
/// 
/// Detects vulnerabilities in Arbitrary Message Bridges where cross-chain
/// message injection, replay, or validation bypass can occur.
/// 
/// **AMB Context**:
/// Arbitrary Message Bridges pass generic messages between chains (not just token transfers).
/// Gnosis Chain AMB is a specific implementation used for xDai<->Ethereum messaging.
/// 
/// **Attack Patterns**:
/// 1. Message injection (forging cross-chain messages)
/// 2. Message replay attacks
/// 3. Validator signature bypass
/// 4. Message ordering manipulation
/// 5. Cross-chain reentrancy via messages
/// 
/// **Detection Strategy**:
/// - Identifies message execution without signature validation
/// - Detects missing message replay protection
/// - Flags validator set updates without proper controls
/// - Checks for message ordering vulnerabilities
/// - Validates cross-chain call authentication
pub struct GnosisAmbBridgeDetector {
    bytecode: Vec<u8>,
}

impl GnosisAmbBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_message_injection_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Cross-chain message can be injected without proper validation - AMB vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Validate message signatures from bridge validators and check message source chain".to_string(),
            });
        }

        if self.has_message_replay_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Cross-chain messages vulnerable to replay attacks".to_string(),
                operations: Vec::new(),
                remediation: "Implement message nonce tracking and mark messages as executed".to_string(),
            });
        }

        if self.has_validator_bypass_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Message validator signatures can be bypassed or forged".to_string(),
                operations: Vec::new(),
                remediation: "Require threshold of validator signatures and verify each signature".to_string(),
            });
        }

        if self.has_message_ordering_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Message execution order can be manipulated".to_string(),
                operations: Vec::new(),
                remediation: "Enforce sequential nonce-based message ordering".to_string(),
            });
        }

        warnings
    }

    fn has_message_injection_vulnerability(&self) -> bool {
        // Pattern: executeMessage() without signature validation
        let execute_msg = [0x2d, 0xf4, 0x61, 0xc0]; // executeMessage() or similar
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == execute_msg {
                    let window = &self.bytecode[i..i+60.min(self.bytecode.len())];
                    
                    // Check for message execution (CALL to target)
                    let executes_message = window.iter().any(|&op| {
                        op == 0xf1 || op == 0xf4 // CALL or DELEGATECALL
                    });
                    
                    // Check for signature validation
                    let validates_signatures = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x01) && // ecrecover
                        w.iter().any(|&op| op == 0x14) && // EQ (compare recovered address)
                        w.iter().any(|&op| op == 0xfd) // REVERT if invalid
                    });
                    
                    // Check for validator set verification
                    let checks_validator_set = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (validator key)
                        w.iter().any(|&op| op == 0x54) && // SLOAD (is validator)
                        w.iter().any(|&op| op == 0x15) // ISZERO (check)
                    });
                    
                    // Check for source chain validation
                    let validates_source_chain = window.windows(8).any(|w| {
                        w.iter().any(|&op| op == 0x35) && // CALLDATALOAD (chainId)
                        w.iter().any(|&op| op == 0x14) // EQ (expected chain)
                    });
                    
                    if executes_message && !validates_signatures && !checks_validator_set && !validates_source_chain {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_message_replay_vulnerability(&self) -> bool {
        // Pattern: message execution without nonce/replay protection
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL or DELEGATECALL (message execution)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check if this is cross-chain message execution
                let is_message_execution = window.windows(15).any(|w| {
                    w.iter().any(|&op| op == 0x35 || op == 0x36) && // CALLDATALOAD (message data)
                    w.iter().any(|&op| op == 0xf1 || op == 0xf4) // Execute
                });
                
                if is_message_execution {
                    // Check for nonce tracking
                    let tracks_nonce = window.windows(15).any(|w| {
                        // Pattern: SLOAD(nonce) -> increment -> SSTORE
                        w.iter().any(|&op| op == 0x54) && // SLOAD (current nonce)
                        w.iter().any(|&op| op == 0x01) && // ADD (increment)
                        w.iter().any(|&op| op == 0x55) // SSTORE (update nonce)
                    });
                    
                    // Check for executed flag
                    let marks_executed = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (message hash)
                        w.iter().any(|&op| op == 0x60) && // PUSH1 (true/1)
                        w.iter().any(|&op| op == 0x55) // SSTORE (mark executed)
                    });
                    
                    if !tracks_nonce && !marks_executed {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_validator_bypass_risk(&self) -> bool {
        // Pattern: insufficient validator signature validation
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x01 { // ecrecover
                let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                
                // Check if used for message validation
                let validates_message = window.windows(15).any(|w| {
                    w.iter().any(|&op| op == 0x20) && // KECCAK256 (message hash)
                    w.iter().any(|&op| op == 0x01) // ecrecover
                });
                
                if validates_message {
                    // Check for threshold validation (multiple signatures)
                    let has_threshold = window.windows(20).any(|w| {
                        w.iter().filter(|&&op| op == 0x01).count() >= 2 && // Multiple ecrecover
                        w.iter().any(|&op| op == 0x01) && // ADD (count sigs)
                        w.iter().any(|&op| op == 0x11) // GT (check threshold)
                    });
                    
                    // Check for validator whitelist
                    let checks_whitelist = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (validator key)
                        w.iter().any(|&op| op == 0x54) // SLOAD (is validator)
                    });
                    
                    if !has_threshold && !checks_whitelist {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_message_ordering_vulnerability(&self) -> bool {
        // Pattern: messages executed out of order
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for message execution
            if self.bytecode[i] == 0xf1 { // CALL (execute message)
                let window = &self.bytecode[i.saturating_sub(35)..i+10.min(self.bytecode.len())];
                
                // Check if processing cross-chain messages
                let processes_messages = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x35) && // CALLDATALOAD (message)
                    w.iter().any(|&op| op == 0xf1) // CALL (execute)
                });
                
                if processes_messages {
                    // Check for sequential nonce enforcement
                    let enforces_sequence = window.windows(15).any(|w| {
                        // Pattern: require(nonce == expectedNonce++)
                        w.iter().any(|&op| op == 0x54) && // SLOAD (expected nonce)
                        w.iter().any(|&op| op == 0x14) && // EQ (check match)
                        w.iter().any(|&op| op == 0x01) && // ADD (increment)
                        w.iter().any(|&op| op == 0x55) // SSTORE (update expected)
                    });
                    
                    if !enforces_sequence {
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
    fn test_gnosis_amb_message_injection() {
        let vulnerable_bytecode = vec![
            0x63, 0x2d, 0xf4, 0x61, 0xc0, // executeMessage()
            0x35, // CALLDATALOAD (message)
            0xf1, // CALL (execute - no signature validation!)
        ];

        let detector = GnosisAmbBridgeDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("message") || w.description.contains("injection")));
    }
}
