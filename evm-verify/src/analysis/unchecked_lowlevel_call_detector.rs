/// Unchecked Low-Level Call Return Value Detector
///
/// Detects when low-level calls (.call, .delegatecall, .staticcall) 
/// have their return values ignored, causing silent failures.
///
/// Why dangerous:
/// - .call() returns (bool success, bytes memory data)
/// - Ignoring bool = transaction continues after failure
/// - Silent fund loss, broken state, undetected errors
/// - **$10M+ in silent failure exploits**
///
/// Example:
/// ```solidity
/// contract UncheckedCall {
///     function sendEther(address payable recipient) external payable {
///         // ❌ CRITICAL: Ignores return value!
///         recipient.call{value: msg.value}("");
///         // If call fails, ether is NOT sent but code continues!
///     }
///     
///     // ✓ CORRECT:
///     function sendEtherSafe(address payable recipient) external payable {
///         (bool success,) = recipient.call{value: msg.value}("");
///         require(success, "Transfer failed");
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncheckedCallVulnerability {
    pub vulnerability_type: UncheckedCallType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UncheckedCallType {
    UncheckedCall,                 // CALL without success check
    UncheckedDelegatecall,         // DELEGATECALL without check
    UncheckedStaticcall,           // STATICCALL without check
}

pub struct UncheckedLowLevelCallDetector {
    bytecode: Vec<u8>,
}

impl UncheckedLowLevelCallDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UncheckedCallVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            match self.bytecode[i] {
                0xF1 => { // CALL
                    if !self.has_success_check_after(i) {
                        vulnerabilities.push(UncheckedCallVulnerability {
                            vulnerability_type: UncheckedCallType::UncheckedCall,
                            severity: SecuritySeverity::High,
                            confidence: 0.70,
                            description: "CALL without return value check".to_string(),
                            exploit_scenario: format!(
                                "UNCHECKED CALL at {}:\n\
                                Low-level call without checking success.\n\
                                If call fails, execution continues silently!\n\
                                \n\
                                SAFE: (bool s,) = addr.call{{}}(\"\"); require(s);",
                                i
                            ),
                            location: i,
                        });
                    }
                }
                0xF4 => { // DELEGATECALL  
                    if !self.has_success_check_after(i) {
                        vulnerabilities.push(UncheckedCallVulnerability {
                            vulnerability_type: UncheckedCallType::UncheckedDelegatecall,
                            severity: SecuritySeverity::Critical,
                            confidence: 0.75,
                            description: "DELEGATECALL without return value check".to_string(),
                            exploit_scenario: "DELEGATECALL unchecked - verify success validation".to_string(),
                            location: i,
                        });
                    }
                }
                0xFA => { // STATICCALL
                    if !self.has_success_check_after(i) {
                        vulnerabilities.push(UncheckedCallVulnerability {
                            vulnerability_type: UncheckedCallType::UncheckedStaticcall,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.65,
                            description: "STATICCALL without return value check".to_string(),
                            exploit_scenario: "STATICCALL unchecked - verify success validation".to_string(),
                            location: i,
                        });
                    }
                }
                _ => {}
            }
        }

        vulnerabilities
    }

    fn has_success_check_after(&self, pos: usize) -> bool {
        // Look for ISZERO or JUMPI (conditional check) within next 20 bytes
        for i in pos+1..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x15 || // ISZERO
               self.bytecode[i] == 0x57 || // JUMPI
               self.bytecode[i] == 0xFD { // REVERT
                return true;
            }
        }
        false
    }
}
