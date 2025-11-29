/// ERC-7579 Modular Account Detector
/// Detects vulnerabilities in modular smart account standard (2024)
/// Critical for: Safe, Kernel, Biconomy v2 modular accounts

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ERC7579Vulnerability {
    pub vulnerability_type: ERC7579IssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC7579IssueType {
    ModuleInstallationBypass,      // Install module without authorization
    ExecutionSelectorCollision,    // Selector collision between modules
    ModuleHookManipulation,        // Hook execution order manipulation
    FallbackHandlerExploit,        // Fallback handler unauthorized access
    ModuleUninstallVulnerability,  // Module can't be uninstalled safely
    ValidationModuleConflict,      // Multiple validation modules conflict
}

pub struct ERC7579Detector {
    bytecode: Vec<u8>,
}

impl ERC7579Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ERC7579Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_erc7579_account() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_module_installation_issues());
        vulnerabilities.extend(self.detect_selector_collision());
        vulnerabilities.extend(self.detect_hook_manipulation());

        vulnerabilities
    }

    fn detect_module_installation_issues(&self) -> Vec<ERC7579Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: installModule without proper authorization
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let install = [0x6d, 0x61, 0xfe, 0x70]; // installModule
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &install {
                if !self.has_authorization_check(i) {
                    vulnerabilities.push(ERC7579Vulnerability {
                        vulnerability_type: ERC7579IssueType::ModuleInstallationBypass,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: "Module can be installed without owner authorization".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker calls installModule(maliciousModule)\n\
                            2. No check if caller is owner\n\
                            3. Malicious module installed\n\
                            4. Module gains account control\n\
                            5. Funds drained\n\n\
                            Fix: require(msg.sender == address(this)) // via execute",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_selector_collision(&self) -> Vec<ERC7579Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Multiple DELEGATECALL without collision check
        let mut delegatecall_count = 0;
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xF4 { // DELEGATECALL
                delegatecall_count += 1;
            }
        }

        if delegatecall_count >= 2 {
            vulnerabilities.push(ERC7579Vulnerability {
                vulnerability_type: ERC7579IssueType::ExecutionSelectorCollision,
                severity: SecuritySeverity::High,
                confidence: 0.70,
                description: "Multiple modules without selector collision protection".to_string(),
                exploit_scenario: format!(
                    "Multiple DELEGATECALL patterns detected:\n\
                    1. Module A implements function foo()\n\
                    2. Module B also implements foo() with same selector\n\
                    3. Router doesn't detect collision\n\
                    4. Wrong module executes\n\
                    5. Unexpected behavior\n\n\
                    Fix: Check for selector uniqueness at installation"
                ),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn detect_hook_manipulation(&self) -> Vec<ERC7579Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Hook execution without validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xF4 && // DELEGATECALL (hook)
               self.is_in_hook_context(i) {
                if !self.has_hook_validation(i) {
                    vulnerabilities.push(ERC7579Vulnerability {
                        vulnerability_type: ERC7579IssueType::ModuleHookManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Hook module executed without validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Hook module registered for beforeTransaction\n\
                            2. No validation of hook return value\n\
                            3. Malicious hook returns manipulated data\n\
                            4. Transaction proceeds with bad data\n\n\
                            Fix: Validate hook return values",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_erc7579_account(&self) -> bool {
        let install = [0x6d, 0x61, 0xfe, 0x70]; // installModule
        let execute = [0xb6, 0x1d, 0x27, 0xf6]; // execute with mode
        self.bytecode.windows(4).any(|w| w == install || w == execute)
    }

    fn has_authorization_check(&self, pos: usize) -> bool {
        // Look for CALLER check (msg.sender == address(this))
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x33 && i + 2 < self.bytecode.len() && self.bytecode[i + 2] == 0x14 {
                return true;
            }
        }
        false
    }

    fn is_in_hook_context(&self, pos: usize) -> bool {
        // Heuristic: DELEGATECALL in module execution path
        pos > 50 // Simplification
    }

    fn has_hook_validation(&self, pos: usize) -> bool {
        // Look for return value check after DELEGATECALL
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x15 { // ISZERO (check return)
                return true;
            }
        }
        false
    }
}
