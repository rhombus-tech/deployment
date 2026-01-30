use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stipend2300Vulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// 2300 Gas Stipend Griefing Detector
///
/// Detects vulnerabilities related to the 2300 gas stipend sent with .transfer() and .send(),
/// which can be exploited for griefing attacks or cause unexpected failures.
///
/// Vulnerability Scenarios:
/// - Griefing by making fallback/receive consume >2300 gas
/// - DOS attacks via gas-intensive fallback functions
/// - Failed transfers due to increased SLOAD costs (post-Istanbul)
/// - Smart contract wallets unable to receive with 2300 gas
/// - Multisig wallets breaking due to gas limits
///
/// Real-World Cases:
/// - Many contracts broke after Istanbul hard fork (SLOAD cost increase)
/// - Smart contract wallets unable to receive ETH
/// - Griefing attacks in DeFi protocols
/// - Withdrawal failures in exchanges
///
/// Detection Strategy:
/// - Identifies CALL with exactly 2300 gas stipend
/// - Detects .transfer() and .send() patterns
/// - Looks for unchecked return values from send()
/// - Checks for griefing-vulnerable patterns
/// - Identifies contracts relying on 2300 gas assumption
pub struct Stipend2300GasGriefingDetector;

impl Stipend2300GasGriefingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: CALL with 2300 gas stipend (transfer/send)
            if bytecode[i] == 0xf1 {
                if self.has_2300_gas_stipend(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "2300 gas stipend: Using .transfer() or .send() with 2300 gas vulnerable to griefing and post-Istanbul failures".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 2: Unchecked send() return value
            if bytecode[i] == 0xf1 {
                if self.has_unchecked_send_return(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Unchecked send() return: Ignoring .send() failure enables griefing and fund loss".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 3: Withdrawal pattern with 2300 gas
            if bytecode[i] == 0xf1 {
                if self.has_withdrawal_with_2300_gas(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Withdrawal 2300 gas: Withdrawal function uses 2300 gas stipend, fails for smart contract recipients".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 4: Iteration with transfer() (griefing DoS)
            if bytecode[i] == 0xf1 {
                if self.has_loop_transfer_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Loop transfer griefing: Multiple transfers in loop vulnerable to DoS via single griefing recipient".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 5: Push payment with transfer() (anti-pattern)
            if bytecode[i] == 0xf1 {
                if self.has_push_payment_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Push payment pattern: Using transfer() for push payments is anti-pattern, prefer pull pattern".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<Stipend2300Vulnerability> {
        self.detect(bytecode)
            .into_iter()
            .map(|finding| Stipend2300Vulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_2300_gas_stipend(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 15.min(pos);
        let mut has_2300_gas = false;
        let mut has_value = false;

        // Check for 2300 (0x08fc) gas parameter before CALL
        for offset in 1..=lookback {
            if pos >= offset {
                // PUSH2 0x08fc (2300 in hex)
                if bytecode[pos - offset] == 0x61 && pos >= offset + 2 {
                    if bytecode.get(pos - offset + 1) == Some(&0x08) 
                        && bytecode.get(pos - offset + 2) == Some(&0xfc) {
                        has_2300_gas = true;
                    }
                }
                // Check for non-zero value (transfer/send sends value)
                if matches!(bytecode[pos - offset], 0x60..=0x7f) {
                    has_value = true;
                }
            }
        }

        // CALL with 2300 gas and value
        has_2300_gas && has_value
    }

    fn has_unchecked_send_return(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 15.min(pos);
        let window = 10.min(bytecode.len().saturating_sub(pos));
        
        let mut has_2300_gas = false;
        let mut return_value_checked = false;

        // Check for 2300 gas (send pattern)
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x61 && pos >= offset + 2 {
                    if bytecode.get(pos - offset + 1) == Some(&0x08) 
                        && bytecode.get(pos - offset + 2) == Some(&0xfc) {
                        has_2300_gas = true;
                    }
                }
            }
        }

        // Check if return value is used
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x15 => return_value_checked = true, // ISZERO (checking return)
                    0x57 => return_value_checked = true, // JUMPI (conditional on return)
                    0x50 => return_value_checked = false, // POP (ignoring return!)
                    _ => {}
                }
            }
        }

        // send() with unchecked return value
        has_2300_gas && !return_value_checked
    }

    fn has_withdrawal_with_2300_gas(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_2300_gas = false;
        let mut has_sload = false;
        let mut has_balance_check = false;

        // Check for 2300 gas
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x61 && pos >= offset + 2 {
                    if bytecode.get(pos - offset + 1) == Some(&0x08) 
                        && bytecode.get(pos - offset + 2) == Some(&0xfc) {
                        has_2300_gas = true;
                    }
                }
                if bytecode[pos - offset] == 0x54 {
                    has_sload = true; // SLOAD (reading balance)
                }
                if bytecode[pos - offset] == 0x47 {
                    has_balance_check = true; // SELFBALANCE
                }
            }
        }

        // Withdrawal pattern with 2300 gas
        has_2300_gas && (has_sload || has_balance_check)
    }

    fn has_loop_transfer_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut has_2300_gas = false;
        let mut has_loop = false;
        let mut has_array_access = false;

        // Check for loop structure with transfer
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x61 => {
                        if pos >= offset + 2 {
                            if bytecode.get(pos - offset + 1) == Some(&0x08) 
                                && bytecode.get(pos - offset + 2) == Some(&0xfc) {
                                has_2300_gas = true;
                            }
                        }
                    }
                    0x57 => has_loop = true, // JUMPI (loop)
                    0x02 => has_array_access = true, // MUL (array indexing)
                    _ => {}
                }
            }
        }

        // Multiple transfers in loop
        has_2300_gas && has_loop && has_array_access
    }

    fn has_push_payment_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let window = 20.min(bytecode.len().saturating_sub(pos));
        
        let mut has_2300_gas = false;
        let mut has_multiple_recipients = false;
        let mut has_state_change_before = false;

        // Check for 2300 gas
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x61 && pos >= offset + 2 {
                    if bytecode.get(pos - offset + 1) == Some(&0x08) 
                        && bytecode.get(pos - offset + 2) == Some(&0xfc) {
                        has_2300_gas = true;
                    }
                }
                // State changes before payment (push pattern)
                if bytecode[pos - offset] == 0x55 {
                    has_state_change_before = true;
                }
                // Array or multiple addresses
                if bytecode[pos - offset] == 0x02 || bytecode[pos - offset] == 0x57 {
                    has_multiple_recipients = true;
                }
            }
        }

        // Check for revert after failed transfer
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0xfd {
                    // REVERT after transfer suggests reliance on success
                    return true;
                }
            }
        }

        // Push payment: state change then transfer
        has_2300_gas && has_state_change_before && !has_multiple_recipients
    }
}
