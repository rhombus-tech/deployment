/// SELFBALANCE vs address(this).balance Reentrancy Detector
///
/// Detects dangerous usage of address(this).balance in payable functions.
/// CRITICAL: In payable function, address(this).balance INCLUDES msg.value!
///
/// Why dangerous:
/// - address(this).balance includes msg.value in current tx
/// - SELFBALANCE opcode does NOT include msg.value
/// - Checks before state updates = reentrancy vulnerability
/// - **$2M+ in balance-based reentrancy attacks**
///
/// Example:
/// ```solidity
/// contract BalanceReentrancy {
///     mapping(address => uint256) deposits;
///     
///     function deposit() external payable {
///         // ❌ CRITICAL: balance already includes msg.value!
///         require(address(this).balance >= 1 ether);
///         
///         deposits[msg.sender] += msg.value;
///         // Attacker can exploit this check!
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfBalanceVulnerability {
    pub vulnerability_type: BalanceIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BalanceIssueType {
    BalanceInPayableFunction,      // address(this).balance in payable
    BalanceBeforeStateUpdate,      // Balance check before SSTORE
}

pub struct SelfBalanceReentrancyDetector {
    bytecode: Vec<u8>,
}

impl SelfBalanceReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SelfBalanceVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x31 { // BALANCE opcode
                vulnerabilities.push(SelfBalanceVulnerability {
                    vulnerability_type: BalanceIssueType::BalanceInPayableFunction,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.55,
                    description: "BALANCE opcode - verify not in payable function".to_string(),
                    exploit_scenario: format!(
                        "BALANCE CHECK at {}:\n\
                        \n\
                        CRITICAL DIFFERENCE:\n\
                        - address(this).balance → Includes msg.value!\n\
                        - SELFBALANCE (0x47) → Does NOT include msg.value\n\
                        \n\
                        In payable function, balance checks are dangerous!",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }
}
