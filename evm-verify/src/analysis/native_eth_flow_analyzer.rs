/// Native ETH Flow Analyzer
/// Detects vulnerabilities in native ETH (Ether) handling through receive()/fallback()
/// functions, including stuck funds, unexpected state changes, and reentrancy
///
/// Common issues: ETH sent to contracts that can't withdraw it, balance manipulation

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeETHVulnerability {
    pub vulnerability_type: NativeETHIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NativeETHIssueType {
    StuckETH,                      // ETH can enter but not exit
    UnprotectedSelfDestruct,       // Can force-send ETH via selfdestruct
    BalanceManipulation,           // Uses address(this).balance incorrectly
    MissingPayableCheck,           // Function should be payable but isn't
    ReceiveFallbackConfusion,      // Both receive() and fallback() with different logic
    UnexpectedETHAcceptance,       // Accepts ETH without tracking
}

pub struct NativeETHFlowAnalyzer {
    bytecode: Vec<u8>,
}

impl NativeETHFlowAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<NativeETHVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Accepts ETH but has no withdraw function
        vulnerabilities.extend(self.detect_stuck_eth());

        // Pattern 2: Uses address(this).balance without protection
        vulnerabilities.extend(self.detect_balance_manipulation());

        // Pattern 3: Selfdestruct without access control
        vulnerabilities.extend(self.detect_unprotected_selfdestruct());

        // Pattern 4: receive() and fallback() with inconsistent logic
        vulnerabilities.extend(self.detect_receive_fallback_confusion());

        vulnerabilities
    }

    /// Detect: Contract accepts ETH but has no way to withdraw it
    fn detect_stuck_eth(&self) -> Vec<NativeETHVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_receive = self.has_receive_function();
        let has_payable_fallback = self.has_payable_fallback();
        let accepts_eth = has_receive || has_payable_fallback;

        if accepts_eth {
            let has_withdraw = self.has_eth_withdrawal_function();
            let has_selfdestruct = self.has_selfdestruct();

            if !has_withdraw && !has_selfdestruct {
                vulnerabilities.push(NativeETHVulnerability {
                    vulnerability_type: NativeETHIssueType::StuckETH,
                    severity: SecuritySeverity::High,
                    confidence: 0.85,
                    description:
                        "Contract accepts ETH via receive()/fallback() but has no withdrawal mechanism. \
                        ETH sent to this contract will be permanently stuck.".to_string(),
                    exploit_scenario:
                        "Impact:\n\
                         1. User accidentally sends ETH to contract\n\
                         2. No withdraw() or rescue function exists\n\
                         3. ETH is permanently locked\n\
                         4. Common in contracts not designed to hold ETH\n\n\
                         Real cases: Millions of ETH stuck in contracts without withdrawal".to_string(),
                    location: 0,
                });
            }
        }

        vulnerabilities
    }

    /// Detect: Uses address(this).balance for critical logic
    fn detect_balance_manipulation(&self) -> Vec<NativeETHVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(20) {
            // Look for: SELFBALANCE or ADDRESS + BALANCE
            if self.is_balance_check(pc) {
                // Check if balance is used in conditional (IF/JUMPI)
                let used_in_conditional = self.has_conditional_after(pc, 10);
                // Check if balance is used in arithmetic
                let used_in_arithmetic = self.has_arithmetic_after(pc, 10);

                if used_in_conditional || used_in_arithmetic {
                    vulnerabilities.push(NativeETHVulnerability {
                        vulnerability_type: NativeETHIssueType::BalanceManipulation,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.75,
                        description: format!(
                            "Contract logic at PC {} depends on address(this).balance. \
                            Attacker can manipulate this by force-sending ETH via selfdestruct.",
                            pc
                        ),
                        exploit_scenario:
                            "Attack:\n\
                             1. Contract checks: require(address(this).balance >= X)\n\
                             2. Attacker creates contract with selfdestruct\n\
                             3. selfdestruct(target) force-sends ETH\n\
                             4. address(this).balance increases unexpectedly\n\
                             5. Logic breaks or attacker bypasses checks\n\n\
                             Fix: Track received ETH explicitly, don't rely on balance".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Selfdestruct without access control
    fn detect_unprotected_selfdestruct(&self) -> Vec<NativeETHVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(selfdestruct_pc) = self.find_selfdestruct() {
            // Check if there's access control before selfdestruct
            let has_access_control = self.has_access_control_before(selfdestruct_pc, 100);

            if !has_access_control {
                vulnerabilities.push(NativeETHVulnerability {
                    vulnerability_type: NativeETHIssueType::UnprotectedSelfDestruct,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.90,
                    description:
                        "selfdestruct() has no access control. Anyone can destroy the contract \
                        and force-send all ETH to arbitrary address.".to_string(),
                    exploit_scenario:
                        "Critical vulnerability:\n\
                         1. Attacker calls unprotected selfdestruct function\n\
                         2. Contract is destroyed\n\
                         3. All ETH sent to attacker's address\n\
                         4. Contract permanently disabled\n\n\
                         Real example: Parity multisig hack ($150M frozen)".to_string(),
                    location: selfdestruct_pc,
                });
            }
        }

        vulnerabilities
    }

    /// Detect: Both receive() and fallback() present with different logic
    fn detect_receive_fallback_confusion(&self) -> Vec<NativeETHVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_receive = self.has_receive_function();
        let has_fallback = self.has_fallback_function();

        if has_receive && has_fallback {
            // This itself isn't a vulnerability, but worth noting
            vulnerabilities.push(NativeETHVulnerability {
                vulnerability_type: NativeETHIssueType::ReceiveFallbackConfusion,
                severity: SecuritySeverity::Low,
                confidence: 0.60,
                description:
                    "Contract has both receive() and fallback(). Ensure they handle ETH \
                    consistently to avoid confusion.".to_string(),
                exploit_scenario:
                    "Potential issue:\n\
                     - receive() called when msg.data is empty\n\
                     - fallback() called when msg.data is not empty\n\
                     - If they have different logic, users may be confused\n\
                     - Best practice: Have one forward to the other".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    // Helper methods

    fn has_receive_function(&self) -> bool {
        // receive() has empty function selector (0x00000000)
        // Look for function that accepts ETH with no calldata
        self.bytecode.windows(10).any(|window| {
            window.contains(&0x34) // CALLVALUE - checks msg.value
        })
    }

    fn has_payable_fallback(&self) -> bool {
        // Fallback function typically at end of bytecode
        // Look for default function dispatcher
        self.bytecode.len() > 100 && self.bytecode[self.bytecode.len() - 100..]
            .contains(&0x00) // STOP at end
    }

    fn has_fallback_function(&self) -> bool {
        // Similar to receive but may have calldata checks
        self.has_payable_fallback()
    }

    fn has_eth_withdrawal_function(&self) -> bool {
        // Look for: CALL with value (ETH transfer out)
        let mut pc = 0;
        
        while pc < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[pc] == 0xF1 { // CALL
                // Check if this CALL transfers value (has non-zero gas parameter)
                // Simplified check: just look for CALL opcode
                return true;
            }
            pc += 1;
        }
        
        false
    }

    fn has_selfdestruct(&self) -> bool {
        self.bytecode.contains(&0xFF) // SELFDESTRUCT opcode
    }

    fn find_selfdestruct(&self) -> Option<usize> {
        self.bytecode.iter().position(|&op| op == 0xFF)
    }

    fn has_access_control_before(&self, pc: usize, distance: usize) -> bool {
        let start = pc.saturating_sub(distance);
        
        // Look for: caller check (CALLER, EQ, JUMPI pattern)
        for i in start..pc {
            if i + 3 < pc {
                if self.bytecode[i] == 0x33 && // CALLER
                   self.bytecode[i + 1] == 0x14 && // EQ
                   self.bytecode[i + 2] == 0x57 { // JUMPI
                    return true;
                }
            }
        }
        
        false
    }

    fn is_balance_check(&self, pc: usize) -> bool {
        if pc >= self.bytecode.len() {
            return false;
        }

        // SELFBALANCE (0x47) or ADDRESS + BALANCE pattern
        self.bytecode[pc] == 0x47 || // SELFBALANCE
        (self.bytecode[pc] == 0x30 && // ADDRESS
         pc + 1 < self.bytecode.len() &&
         self.bytecode[pc + 1] == 0x31) // BALANCE
    }

    fn has_conditional_after(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        self.bytecode[pc..end].iter()
            .any(|&op| op == 0x57 || op == 0x56) // JUMPI or JUMP
    }

    fn has_arithmetic_after(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        self.bytecode[pc..end].iter()
            .any(|&op| matches!(op, 0x01..=0x05 | 0x10 | 0x11)) // ADD, MUL, SUB, DIV, MOD, LT, GT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stuck_eth() {
        // Contract with receive() but no withdraw
        let bytecode = vec![
            0x34, // CALLVALUE (receive function)
            0x15, // ISZERO
            0x57, // JUMPI
            // No CALL opcode = no withdrawal
            0x00, // STOP
        ];
        
        let analyzer = NativeETHFlowAnalyzer::new(bytecode);
        let vulns = analyzer.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect stuck ETH");
    }

    #[test]
    fn test_balance_manipulation() {
        let bytecode = vec![
            0x47, // SELFBALANCE
            0x10, // LT (comparison)
            0x57, // JUMPI (conditional based on balance)
        ];
        
        let analyzer = NativeETHFlowAnalyzer::new(bytecode);
        let vulns = analyzer.detect_vulnerabilities();
        
        let has_balance_vuln = vulns.iter()
            .any(|v| matches!(v.vulnerability_type, NativeETHIssueType::BalanceManipulation));
        
        assert!(has_balance_vuln, "Should detect balance manipulation");
    }
}
