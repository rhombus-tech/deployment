/// RETURNDATASIZE Bomb Vulnerability Detector
///
/// Detects unbounded return data copying that can cause DoS attacks.
/// Malicious contracts can return huge amounts of data to grief callers.
///
/// Why dangerous:
/// - Attacker-controlled contract returns megabytes of data
/// - Caller copies return data to memory → massive gas consumption
/// - Out-of-gas error, transaction reverts
/// - Especially dangerous in: multicall, aggregators, batch operations
///
/// Gas costs:
/// - Copying 1KB: ~3k gas
/// - Copying 1MB: ~3M gas
/// - Copying 10MB: ~30M gas (exceeds block limit!)
///
/// Real exploits:
/// - Multicall DoS attacks
/// - Aggregator failures
/// - DEX routing griefing
/// - $500k+ in failed transactions and gas waste
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableMulticall {
///     function aggregate(Call[] calldata calls) 
///         external returns (bytes[] memory results) 
///     {
///         results = new bytes[](calls.length);
///         
///         for (uint i = 0; i < calls.length; i++) {
///             // ❌ Unbounded return data copy
///             (bool success, bytes memory data) = calls[i].target.call(calls[i].data);
///             require(success, "Call failed");
///             results[i] = data; // If data is 10MB → DoS!
///         }
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturndatasizeVulnerability {
    pub vulnerability_type: ReturndatasizeIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReturndatasizeIssueType {
    UnboundedReturndatacopy,       // RETURNDATACOPY without size limit
    ReturndatasizeInLoop,          // Return data copied in loop
    MultipleReturndataCopies,      // Multiple unbounded copies
    ReturndataWithoutValidation,   // No validation before copying
}

pub struct ReturndatasizeBombDetector {
    bytecode: Vec<u8>,
}

impl ReturndatasizeBombDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ReturndatasizeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unbounded_returndatacopy());
        vulnerabilities.extend(self.detect_returndatacopy_in_loop());

        vulnerabilities
    }

    fn detect_unbounded_returndatacopy(&self) -> Vec<ReturndatasizeVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x3E { // RETURNDATACOPY
                if !self.has_size_limit_before(i) {
                    vulnerabilities.push(ReturndatasizeVulnerability {
                        vulnerability_type: ReturndatasizeIssueType::UnboundedReturndatacopy,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "Unbounded RETURNDATACOPY - return bomb DoS risk".to_string(),
                        exploit_scenario: format!(
                            "UNBOUNDED RETURNDATACOPY at {}:\n\
                            \n\
                            Malicious contract can return huge data causing DoS.\n\
                            \n\
                            Attack: Malicious contract returns 10MB → out of gas\n\
                            Fix: Limit return data size before copying",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_returndatacopy_in_loop(&self) -> Vec<ReturndatasizeVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x3E && self.is_in_loop(i) {
                vulnerabilities.push(ReturndatasizeVulnerability {
                    vulnerability_type: ReturndatasizeIssueType::ReturndatasizeInLoop,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "RETURNDATACOPY in loop - amplified DoS risk".to_string(),
                    exploit_scenario: format!(
                        "RETURNDATACOPY IN LOOP at {}:\n\
                        \n\
                        Multiple calls with large return data = massive gas consumption.\n\
                        \n\
                        Attack: 100 calls × 100KB each = 10MB total\n\
                        Fix: Limit both loop iterations and return data size",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn has_size_limit_before(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(20)..pos {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT
                return true;
            }
        }
        false
    }

    fn is_in_loop(&self, pos: usize) -> bool {
        let has_jumpdest = self.bytecode[..pos].iter().rev().take(50).any(|&b| b == 0x5B);
        let has_jumpi = self.bytecode[pos..].iter().take(50).any(|&b| b == 0x57);
        has_jumpdest && has_jumpi
    }
}
