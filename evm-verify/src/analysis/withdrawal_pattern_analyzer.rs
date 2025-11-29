// Withdrawal Pattern Analyzer
// Detects pull vs push payment anti-patterns and withdrawal vulnerabilities
// Historical: Countless DAO/DeFi hacks, withdrawal reentrancy

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalVulnerability {
    pub vulnerability_type: WithdrawalPatternType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WithdrawalPatternType {
    PushPaymentAntiPattern,      // Sending ETH in loops or to arbitrary addresses
    UncheckedWithdrawalAmount,   // No balance check before withdrawal
    WithdrawalReentrancy,        // State updated after external call
    MissingWithdrawalLimit,      // No rate limiting on withdrawals
    UnlimitedEmergencyWithdraw,  // Admin can withdraw all funds
    WithdrawalToZeroAddress,     // No check for address(0)
    FailedWithdrawalSilent,      // Withdrawal failure not handled
    BatchWithdrawalDOS,          // Batch operations can be blocked
    WithdrawalFrontRunning,      // Withdrawal vulnerable to front-running
    MissingPullPaymentPattern,   // Should use pull but uses push
}

pub struct WithdrawalPatternAnalyzer {
    bytecode: Vec<u8>,
}

impl WithdrawalPatternAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<WithdrawalVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_push_payment_pattern());
        vulnerabilities.extend(self.detect_unchecked_withdrawal());
        vulnerabilities.extend(self.detect_withdrawal_reentrancy());
        vulnerabilities.extend(self.detect_emergency_withdraw_abuse());
        vulnerabilities.extend(self.detect_batch_withdrawal_dos());
        vulnerabilities.extend(self.detect_failed_withdrawal_handling());

        vulnerabilities
    }

    fn detect_push_payment_pattern(&self) -> Vec<WithdrawalVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect CALL with value in loop (push payment anti-pattern)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            // Look for JUMPDEST (loop start) followed by CALL pattern
            if self.bytecode[i] == 0x5b { // JUMPDEST
                // Check next 15 bytes for CALL with value
                let section = &self.bytecode[i..i+15.min(self.bytecode.len()-i)];
                let has_call_with_value = section.windows(3).any(|w| {
                    w[0] == 0xf1 || // CALL
                    (w.contains(&0xf1) && section.contains(&0x34)) // CALL and CALLVALUE
                });

                if has_call_with_value {
                    vulnerabilities.push(WithdrawalVulnerability {
                        vulnerability_type: WithdrawalPatternType::PushPaymentAntiPattern,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Push payment pattern detected in loop - vulnerable to DOS".to_string(),
                        exploit_scenario: "Single failed payment blocks entire batch. Attacker can prevent all withdrawals by causing one to fail".to_string(),
                        remediation: "Use pull payment pattern: users withdraw individually rather than batch push".to_string(),
                    });
                }
            }
            i += 1;
        }

        vulnerabilities
    }

    fn detect_unchecked_withdrawal(&self) -> Vec<WithdrawalVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for CALL with value without preceding balance check
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xf1 { // CALL
                // Check if there's BALANCE (0x31) or SELFBALANCE (0x47) in previous 20 bytes
                let preceding = &self.bytecode[i.saturating_sub(20)..i];
                let has_balance_check = preceding.contains(&0x31) || preceding.contains(&0x47);

                // Check if there's value being sent (non-zero)
                let has_value = preceding.windows(2).any(|w| {
                    w[0] == 0x60 && w[1] > 0 // PUSH1 with non-zero value
                });

                if has_value && !has_balance_check {
                    vulnerabilities.push(WithdrawalVulnerability {
                        vulnerability_type: WithdrawalPatternType::UncheckedWithdrawalAmount,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "ETH transfer without balance check".to_string(),
                        exploit_scenario: "Contract attempts to send more ETH than it holds, causing transaction failure and potential loss of funds".to_string(),
                        remediation: "Always check: require(address(this).balance >= amount)".to_string(),
                    });
                }
            }
            i += 1;
        }

        vulnerabilities
    }

    fn detect_withdrawal_reentrancy(&self) -> Vec<WithdrawalVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: CALL followed by SSTORE (state update after external call)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL or DELEGATECALL
                // Check next 10 bytes for SSTORE
                let following = &self.bytecode[i..i+10.min(self.bytecode.len()-i)];
                if following.contains(&0x55) { // SSTORE
                    vulnerabilities.push(WithdrawalVulnerability {
                        vulnerability_type: WithdrawalPatternType::WithdrawalReentrancy,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "State update after external call - classic reentrancy pattern".to_string(),
                        exploit_scenario: "Attacker can reenter before state is updated, withdrawing multiple times".to_string(),
                        remediation: "Use checks-effects-interactions: update state BEFORE external calls".to_string(),
                    });
                }
            }
            i += 1;
        }

        vulnerabilities
    }

    fn detect_emergency_withdraw_abuse(&self) -> Vec<WithdrawalVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for function that:
        // 1. Checks CALLER (access control)
        // 2. Sends entire balance (SELFBALANCE followed by CALL)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x33 { // CALLER
                let section = &self.bytecode[i..i+30.min(self.bytecode.len()-i)];
                let has_full_balance = section.contains(&0x47); // SELFBALANCE
                let has_call = section.contains(&0xf1); // CALL

                if has_full_balance && has_call {
                    vulnerabilities.push(WithdrawalVulnerability {
                        vulnerability_type: WithdrawalPatternType::UnlimitedEmergencyWithdraw,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Emergency withdraw function can extract all funds".to_string(),
                        exploit_scenario: "Compromised admin key allows instant theft of all contract funds with no timelock or limits".to_string(),
                        remediation: "Add timelock, multi-sig, or percentage limits to emergency withdrawals".to_string(),
                    });
                }
            }
            i += 1;
        }

        vulnerabilities
    }

    fn detect_batch_withdrawal_dos(&self) -> Vec<WithdrawalVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect loop with CALL pattern (batch withdrawal)
        let mut in_loop = false;
        let mut loop_start = 0;

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x5b { // JUMPDEST
                in_loop = true;
                loop_start = i;
            }
            
            if in_loop && self.bytecode[i] == 0x57 { // JUMPI (loop condition)
                // Check if loop contains CALL
                let loop_section = &self.bytecode[loop_start..i.min(self.bytecode.len())];
                if loop_section.contains(&0xf1) {
                    vulnerabilities.push(WithdrawalVulnerability {
                        vulnerability_type: WithdrawalPatternType::BatchWithdrawalDOS,
                        severity: SecuritySeverity::High,
                        location: loop_start,
                        description: "Batch withdrawal in loop can be DOS attacked".to_string(),
                        exploit_scenario: "Attacker causes one withdrawal to fail (via revert in fallback), blocking entire batch".to_string(),
                        remediation: "Use individual withdraw functions or try/catch to continue on failures".to_string(),
                    });
                }
                in_loop = false;
            }
        }

        vulnerabilities
    }

    fn detect_failed_withdrawal_handling(&self) -> Vec<WithdrawalVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for CALL without checking return value (ISZERO or comparison after CALL)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0xf1 { // CALL
                // Check next 5 bytes for return value handling
                let following = &self.bytecode[i+1..i+5.min(self.bytecode.len())];
                let checks_return = following.contains(&0x15) || // ISZERO
                                   following.contains(&0x14) || // EQ
                                   following.contains(&0x57);   // JUMPI

                if !checks_return {
                    vulnerabilities.push(WithdrawalVulnerability {
                        vulnerability_type: WithdrawalPatternType::FailedWithdrawalSilent,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "External call result not checked - failed withdrawal ignored".to_string(),
                        exploit_scenario: "Withdrawal silently fails but user balance is still deducted".to_string(),
                        remediation: "Always check: require(success, 'Transfer failed')".to_string(),
                    });
                }
            }
            i += 1;
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_withdrawal_reentrancy() {
        // CALL followed by SSTORE (vulnerable pattern)
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0xf1,       // CALL
            0x55,       // SSTORE (state update after call)
        ];
        
        let analyzer = WithdrawalPatternAnalyzer::new(bytecode);
        let vulns = analyzer.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, WithdrawalPatternType::WithdrawalReentrancy)));
    }

    #[test]
    fn test_detect_unchecked_withdrawal() {
        // CALL with value but no BALANCE check
        let bytecode = vec![
            0x60, 0x10, // PUSH1 16 (value)
            0xf1,       // CALL
        ];
        
        let analyzer = WithdrawalPatternAnalyzer::new(bytecode);
        let vulns = analyzer.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, WithdrawalPatternType::UncheckedWithdrawalAmount)));
    }
}
