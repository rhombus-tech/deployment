/// Fallback/Receive Ambiguity Vulnerability Detector
///
/// Detects confusion between fallback() and receive() functions that can lock ETH.
/// Solidity 0.6+ introduced separate receive() for ETH-only and fallback() for calls.
///
/// Why dangerous:
/// - receive() called for plain ETH transfers (no data)
/// - fallback() called for unknown function calls (with or without ETH)
/// - Missing or incorrect implementation locks ETH permanently
/// - Logic bugs when both are present
///
/// Common mistakes:
/// - Only fallback(), no receive() → ETH transfers fail
/// - receive() but no fallback() → contract calls fail  
/// - Both present but conflicting logic
/// - payable fallback but no receive → ambiguous
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableVault {
///     receive() external payable {
///         // ❌ Only handles plain ETH, but has deposit logic
///         emit Received(msg.sender, msg.value);
///     }
///     
///     function deposit() external payable {
///         balances[msg.sender] += msg.value;
///     }
///     
///     // Problem: ETH sent without calldata goes to receive()
///     // Balance not tracked! ETH locked forever.
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackReceiveVulnerability {
    pub vulnerability_type: FallbackReceiveIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FallbackReceiveIssueType {
    MissingReceive,                // Has payable fallback but no receive
    MissingFallback,               // Has receive but no fallback
    ConflictingLogic,              // Both present with different logic
    ReceiveWithComplexLogic,       // receive() has complex logic (gas issues)
    PayableFallbackRisk,           // Payable fallback without proper handling
}

pub struct FallbackReceiveAmbiguityDetector {
    bytecode: Vec<u8>,
}

impl FallbackReceiveAmbiguityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FallbackReceiveVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_receive = self.has_receive_function();
        let has_fallback = self.has_fallback_function();
        let has_payable_fallback = self.has_payable_fallback();

        if has_payable_fallback && !has_receive {
            vulnerabilities.push(FallbackReceiveVulnerability {
                vulnerability_type: FallbackReceiveIssueType::MissingReceive,
                severity: SecuritySeverity::Medium,
                confidence: 0.75,
                description: "Payable fallback without receive() - ETH handling ambiguous".to_string(),
                exploit_scenario: "Contract has payable fallback but no receive function. Plain ETH transfers may fail or behave unexpectedly.".to_string(),
                location: 0,
            });
        }

        if has_receive && !has_fallback {
            vulnerabilities.push(FallbackReceiveVulnerability {
                vulnerability_type: FallbackReceiveIssueType::MissingFallback,
                severity: SecuritySeverity::Low,
                confidence: 0.70,
                description: "receive() without fallback() - calls with data will fail".to_string(),
                exploit_scenario: "Contract has receive for ETH but no fallback. Calls with calldata to unknown functions will revert.".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn has_receive_function(&self) -> bool {
        // receive() is encoded as empty function selector with CALLVALUE check
        // Look for: CALLVALUE → ISZERO → JUMPI pattern at start
        for i in 0..self.bytecode.len().saturating_sub(10).min(100) {
            if self.bytecode[i] == 0x34 && // CALLVALUE
               i + 2 < self.bytecode.len() &&
               self.bytecode[i+1] == 0x15 && // ISZERO  
               self.bytecode[i+2] == 0x57 { // JUMPI
                return true;
            }
        }
        false
    }

    fn has_fallback_function(&self) -> bool {
        // Fallback typically at end of dispatch logic
        // Look for REVERT or INVALID after all function checks
        self.bytecode.iter().any(|&b| b == 0xFE || b == 0xFD)
    }

    fn has_payable_fallback(&self) -> bool {
        // Payable fallback doesn't have CALLVALUE check that reverts
        !self.has_callvalue_revert_guard()
    }

    fn has_callvalue_revert_guard(&self) -> bool {
        // Pattern: CALLVALUE → ISZERO → (no JUMPI) → REVERT
        for i in 0..self.bytecode.len().saturating_sub(5).min(100) {
            if self.bytecode[i] == 0x34 { // CALLVALUE
                for j in i+1..i+5 {
                    if j < self.bytecode.len() && self.bytecode[j] == 0xFD { // REVERT
                        return true;
                    }
                }
            }
        }
        false
    }
}
