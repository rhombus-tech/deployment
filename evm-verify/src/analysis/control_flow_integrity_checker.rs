/// Control Flow Integrity (CFI) Checker
/// 
/// Detects when control flow can be hijacked or corrupted
/// Impact: $350M+ in exploits where execution flow is manipulated
/// 
/// Validates:
/// - User-controlled target addresses in CALL/DELEGATECALL
/// - Jump targets computed from user input
/// - Function selector manipulation
/// - Callback address injection
/// - Unrestricted delegatecall targets

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowIntegrityVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub vulnerability_type: CFIViolationType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CFIViolationType {
    UserControlledCallTarget,       // User controls CALL destination
    UserControlledDelegateCall,     // User controls DELEGATECALL target
    DynamicJumpViolation,           // JUMP target from user input
    FunctionSelectorManipulation,   // User controls function selector
    CallbackAddressInjection,       // User provides callback address
    ArbitraryCodeExecution,         // Complete control flow hijack
    IndirectCallViolation,          // Indirect call through user data
}

pub struct ControlFlowIntegrityChecker {
    bytecode: Vec<u8>,
}

impl ControlFlowIntegrityChecker {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ControlFlowIntegrityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. User-controlled CALL targets
        vulnerabilities.extend(self.detect_user_controlled_call());

        // 2. User-controlled DELEGATECALL (critical!)
        vulnerabilities.extend(self.detect_user_controlled_delegatecall());

        // 3. Dynamic JUMP manipulation
        vulnerabilities.extend(self.detect_dynamic_jump_violation());

        // 4. Function selector manipulation
        vulnerabilities.extend(self.detect_function_selector_control());

        // 5. Callback address injection
        vulnerabilities.extend(self.detect_callback_injection());

        vulnerabilities
    }

    fn detect_user_controlled_call(&self) -> Vec<ControlFlowIntegrityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: CALLDATALOAD → CALL (user controls target address)
            if self.has_user_controlled_call_target(pc) {
                vulns.push(ControlFlowIntegrityVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    vulnerability_type: CFIViolationType::UserControlledCallTarget,
                    description: "User can control CALL target address, enabling arbitrary contract execution".to_string(),
                    exploit_scenario: "function execute(address target, bytes memory data) external {\n\
                        // No validation of target!\n\
                        target.call(data); // User controls target\n\
                        }\n\
                        \n\
                        Attack:\n\
                        1. Attacker calls execute(maliciousContract, exploitData)\n\
                        2. Control flow hijacked to attacker's contract\n\
                        3. Malicious contract executes arbitrary code\n\
                        4. Can drain funds, manipulate state, etc.\n\
                        \n\
                        Example: Parity Multisig ($30M)\n\
                        - User-controlled delegatecall target\n\
                        - Attacker called with self-destruct contract\n\
                        - Entire wallet library destroyed".to_string(),
                    remediation: "Whitelist allowed target addresses or remove dynamic call capability".to_string(),
                    confidence: 0.90,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_user_controlled_delegatecall(&self) -> Vec<ControlFlowIntegrityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: CALLDATALOAD → DELEGATECALL (CRITICAL - user controls implementation!)
            if self.has_user_controlled_delegatecall(pc) {
                vulns.push(ControlFlowIntegrityVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    vulnerability_type: CFIViolationType::UserControlledDelegateCall,
                    description: "User controls DELEGATECALL target - complete takeover possible!".to_string(),
                    exploit_scenario: "function upgradeLogic(address newImplementation) external {\n\
                        // No access control!\n\
                        (bool success,) = newImplementation.delegatecall(msg.data);\n\
                        }\n\
                        \n\
                        Attack:\n\
                        1. Attacker provides malicious implementation address\n\
                        2. DELEGATECALL executes malicious code IN THIS CONTRACT'S CONTEXT\n\
                        3. Malicious code has full storage access\n\
                        4. Can steal funds, change owner, destroy contract\n\
                        \n\
                        DELEGATECALL + user control = INSTANT GAME OVER\n\
                        This is THE most dangerous pattern in smart contracts".to_string(),
                    remediation: "NEVER allow user-controlled delegatecall. Use immutable implementation or governance".to_string(),
                    confidence: 0.98,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_dynamic_jump_violation(&self) -> Vec<ControlFlowIntegrityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: User input flows to JUMP/JUMPI destination
            if self.has_dynamic_jump_from_input(pc) {
                vulns.push(ControlFlowIntegrityVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    vulnerability_type: CFIViolationType::DynamicJumpViolation,
                    description: "Jump target computed from user input, can redirect execution".to_string(),
                    exploit_scenario: "// Assembly code with dynamic jump\n\
                        assembly {\n\
                            let jumpDest := calldataload(0x04) // User provides jump target\n\
                            jump(jumpDest) // Jump to user-controlled location!\n\
                        }\n\
                        \n\
                        Attack:\n\
                        1. Attacker provides jump destination\n\
                        2. Can skip access control checks\n\
                        3. Can jump to sensitive code sections\n\
                        4. Bypass intended execution flow".to_string(),
                    remediation: "Use fixed jump tables, validate jump destinations against whitelist".to_string(),
                    confidence: 0.85,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_function_selector_control(&self) -> Vec<ControlFlowIntegrityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: User can manipulate which function gets called
            if self.has_selector_manipulation(pc) {
                vulns.push(ControlFlowIntegrityVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    vulnerability_type: CFIViolationType::FunctionSelectorManipulation,
                    description: "User can control function selector, calling unintended functions".to_string(),
                    exploit_scenario: "function proxy(bytes memory data) external {\n\
                            // Extracts selector from user data\n\
                            bytes4 selector;\n\
                            assembly { selector := mload(add(data, 32)) }\n\
                            \n\
                            // Calls function based on user selector\n\
                            address(this).call(data); // No selector validation!\n\
                        }\n\
                        \n\
                        Attack:\n\
                        1. Attacker crafts data with admin function selector\n\
                        2. proxy() calls admin-only function\n\
                        3. Bypasses access control\n\
                        4. Unauthorized privileged operations".to_string(),
                    remediation: "Validate function selectors against whitelist before proxying".to_string(),
                    confidence: 0.82,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_callback_injection(&self) -> Vec<ControlFlowIntegrityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: User provides callback address that gets called
            if self.has_callback_injection(pc) {
                vulns.push(ControlFlowIntegrityVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    vulnerability_type: CFIViolationType::CallbackAddressInjection,
                    description: "User can inject callback address, enabling reentrancy and control flow manipulation".to_string(),
                    exploit_scenario: "function processWithCallback(address callback, uint amount) external {\n\
                            _transfer(msg.sender, address(this), amount);\n\
                            \n\
                            // Calls user-provided callback\n\
                            ICallback(callback).onTransferReceived();\n\
                            \n\
                            // State updates after callback (dangerous!)\n\
                            processed[msg.sender] = true;\n\
                        }\n\
                        \n\
                        Attack:\n\
                        1. Attacker provides malicious callback address\n\
                        2. Callback reenters processWithCallback()\n\
                        3. processed[attacker] still false\n\
                        4. Double processing, drain funds".to_string(),
                    remediation: "Use reentrancy guard or require callback from trusted registry".to_string(),
                    confidence: 0.88,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions

    fn has_user_controlled_call_target(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: CALLDATALOAD → (push/dup) → CALL
        // User input flows to CALL target position
        let has_calldata = window.iter().position(|&b| b == 0x35); // CALLDATALOAD
        let has_call = window.iter().position(|&b| b == 0xF1 || b == 0xFA); // CALL or STATICCALL

        if let (Some(cd_pos), Some(call_pos)) = (has_calldata, has_call) {
            // Calldata loads before call
            if cd_pos < call_pos {
                // Check if there's NO whitelist validation between them
                let between = &window[cd_pos..call_pos];
                let has_validation = between.windows(3).any(|w| {
                    w[0] == 0x14 && // EQ (checking address)
                    w[1] == 0x15 && // ISZERO
                    w[2] == 0x57    // JUMPI (revert if not whitelisted)
                });

                !has_validation
            } else {
                false
            }
        } else {
            false
        }
    }

    fn has_user_controlled_delegatecall(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: CALLDATALOAD → DELEGATECALL (CRITICAL!)
        let has_calldata = window.iter().position(|&b| b == 0x35); // CALLDATALOAD
        let has_delegatecall = window.iter().position(|&b| b == 0xF4); // DELEGATECALL

        if let (Some(cd_pos), Some(dc_pos)) = (has_calldata, has_delegatecall) {
            cd_pos < dc_pos // User input before delegatecall
        } else {
            false
        }
    }

    fn has_dynamic_jump_from_input(&self, start: usize) -> bool {
        if start + 25 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 25];

        // Look for: CALLDATALOAD → arithmetic → JUMP
        let has_calldata = window.iter().position(|&b| b == 0x35); // CALLDATALOAD
        let has_jump = window.iter().position(|&b| b == 0x56); // JUMP

        if let (Some(cd_pos), Some(j_pos)) = (has_calldata, has_jump) {
            cd_pos < j_pos
        } else {
            false
        }
    }

    fn has_selector_manipulation(&self, start: usize) -> bool {
        if start + 35 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 35];

        // Look for: Extract selector from user data → use in CALL
        // Pattern: CALLDATALOAD → MLOAD (get selector) → CALL
        let has_calldata = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
        let has_mload = window.iter().any(|&b| b == 0x51); // MLOAD (extracting selector)
        let has_call = window.iter().any(|&b| b == 0xF1); // CALL

        has_calldata && has_mload && has_call
    }

    fn has_callback_injection(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];

        // Look for: CALLDATALOAD (callback address) → CALL
        // With SSTORE after (state change after callback = reentrancy risk)
        let calldata_pos = window.iter().position(|&b| b == 0x35); // CALLDATALOAD
        let call_pos = window.iter().position(|&b| b == 0xF1 || b == 0xFA); // CALL
        let sstore_pos = window.iter().position(|&b| b == 0x55); // SSTORE

        matches!((calldata_pos, call_pos, sstore_pos), 
                 (Some(cd), Some(c), Some(ss)) if cd < c && c < ss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_controlled_call() {
        let bytecode = vec![
            0x35, // CALLDATALOAD (user input)
            0xF1, // CALL (user controls target)
            // No validation between
        ];
        
        let checker = ControlFlowIntegrityChecker::new(bytecode);
        let vulns = checker.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, CFIViolationType::UserControlledCallTarget)));
    }
}
