/// Safe{Core} Protocol Plugin Detector
/// Detects vulnerabilities in Safe Protocol plugin system
/// Critical for: Safe wallet ecosystem dominance

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeProtocolVulnerability {
    pub vulnerability_type: SafeProtocolIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafeProtocolIssueType {
    PluginPermissionEscalation,    // Plugin gains more permissions
    PluginReentrancyAttack,        // Plugin reentrancy exploit
    ManagerPrivilegeAbuse,         // Manager role misuse
    HookBypassVulnerability,       // Hook mechanism bypass
    PluginStateCorruption,         // Plugin corrupts Safe state
}

pub struct SafeProtocolDetector {
    bytecode: Vec<u8>,
}

impl SafeProtocolDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SafeProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_safe_plugin() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_permission_issues());
        vulnerabilities.extend(self.detect_reentrancy_risks());

        vulnerabilities
    }

    fn detect_permission_issues(&self) -> Vec<SafeProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_plugin_execution(i) && !self.validates_permissions(i) {
                vulnerabilities.push(SafeProtocolVulnerability {
                    vulnerability_type: SafeProtocolIssueType::PluginPermissionEscalation,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.80,
                    description: "Safe plugin execution without permission validation".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Plugin executes action on Safe\n\
                        2. No validation of plugin permissions\n\
                        3. Plugin escalates privileges\n\
                        4. Drains Safe wallet funds\n\n\
                        Fix: Enforce strict permission checks per action",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_reentrancy_risks(&self) -> Vec<SafeProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_external_call(i) && self.has_state_change_after(i) {
                vulnerabilities.push(SafeProtocolVulnerability {
                    vulnerability_type: SafeProtocolIssueType::PluginReentrancyAttack,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "Safe plugin vulnerable to reentrancy".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Plugin makes external call\n\
                        2. State change occurs after call\n\
                        3. Malicious contract re-enters plugin\n\
                        4. Reentrancy exploit on Safe state\n\n\
                        Fix: Use checks-effects-interactions pattern",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn is_safe_plugin(&self) -> bool {
        // Look for Safe Protocol plugin interface
        let execute_from_plugin = [0x4f, 0x1e, 0xf2, 0x86]; // executeFromPlugin()
        self.bytecode.windows(4).any(|w| w == execute_from_plugin)
    }

    fn has_plugin_execution(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len() && self.bytecode[pos] == 0xF1 // CALL
    }

    fn validates_permissions(&self, pos: usize) -> bool {
        // Look for permission check before execution
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x54 && i + 3 < self.bytecode.len() && self.bytecode[i+3] == 0x14 {
                return true; // SLOAD EQ (permission check)
            }
        }
        false
    }

    fn has_external_call(&self, pos: usize) -> bool {
        pos < self.bytecode.len() &&
        (self.bytecode[pos] == 0xF1 || self.bytecode[pos] == 0xFA) // CALL or STATICCALL
    }

    fn has_state_change_after(&self, pos: usize) -> bool {
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x55 { // SSTORE
                return true;
            }
        }
        false
    }
}
