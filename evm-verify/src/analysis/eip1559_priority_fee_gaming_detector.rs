use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityFeeGamingVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// EIP-1559 Priority Fee Gaming Detector
///
/// Detects vulnerabilities where contracts or bots can game the EIP-1559 priority fee
/// mechanism for MEV extraction, transaction ordering manipulation, or unfair advantages.
///
/// Gaming Mechanisms:
/// - Priority fee manipulation to guarantee transaction ordering
/// - Miner/validator tip gaming for preferential execution
/// - Gas price oracle manipulation via priority fees
/// - Front-running using dynamic priority fees
/// - Back-running with minimal priority fees
///
/// Attack Vectors:
/// - Setting extremely high priority fees for guaranteed inclusion
/// - Gaming auction mechanisms via priority fee control
/// - Exploiting priority fee for timestamp manipulation
/// - DOS via priority fee wars
/// - Cross-block MEV via priority fee strategies
///
/// Real-World Cases:
/// - MEV bots gaming priority fees for profit
/// - DeFi protocols exploited via priority manipulation
/// - NFT mints gamed via priority fee control
/// - Liquidation races won through fee gaming
///
/// Detection Strategy:
/// - Identifies contracts setting custom priority fees
/// - Detects BASEFEE and GASPRICE calculations
/// - Looks for priority fee dependent logic
/// - Checks for MEV-aware transaction construction
/// - Identifies gas price manipulation patterns
pub struct Eip1559PriorityFeeGamingDetector;

impl Eip1559PriorityFeeGamingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: Priority fee calculation (GASPRICE - BASEFEE)
            if bytecode[i] == 0x03 {
                if self.has_priority_fee_calculation(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Priority fee gaming: Contract calculates priority fee (GASPRICE - BASEFEE) for MEV or ordering manipulation".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 2: GASPRICE dependent logic (MEV sensitivity)
            if bytecode[i] == 0x3a {
                if self.has_gasprice_dependent_logic(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Gas price dependency: Logic depends on GASPRICE, vulnerable to priority fee manipulation and MEV".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 3: Dynamic gas price thresholds
            if bytecode[i] == 0x3a {
                if self.has_dynamic_gas_threshold(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Dynamic gas threshold: Contract uses gas price thresholds that can be gamed via priority fees".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 4: Transaction ordering assumptions
            if bytecode[i] == 0x41 {
                if self.has_ordering_assumptions(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Transaction ordering assumption: Contract logic assumes specific ordering, exploitable via priority fee gaming".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            // Pattern 5: Gas refund with priority fee calculation
            if bytecode[i] == 0x48 {
                if self.has_gas_refund_priority_gaming(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Gas refund gaming: Contract refund logic considers priority fees, enabling gaming strategies".to_string(),
                        pc: i,
                        confidence: 0.82,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<PriorityFeeGamingVulnerability> {
        self.detect(bytecode)
            .into_iter()
            .map(|finding| PriorityFeeGamingVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_priority_fee_calculation(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 20.min(pos);
        let mut has_gasprice = false;
        let mut has_basefee = false;
        let mut sub_operation = false;

        // SUB operation with GASPRICE and BASEFEE
        sub_operation = bytecode[pos] == 0x03;

        // Check for GASPRICE and BASEFEE before SUB
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x3a => has_gasprice = true, // GASPRICE
                    0x48 => has_basefee = true, // BASEFEE
                    _ => {}
                }
            }
        }

        // Priority fee = GASPRICE - BASEFEE
        sub_operation && has_gasprice && has_basefee
    }

    fn has_gasprice_dependent_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_conditional = false;
        let mut has_state_change = false;

        // Check for gas price based decisions
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x11 | 0x14 => has_comparison = true, // LT, GT, EQ
                    0x57 => has_conditional = true, // JUMPI
                    0x55 => has_state_change = true, // SSTORE
                    0xf1 | 0xfa => has_state_change = true, // CALL, STATICCALL
                    _ => {}
                }
            }
        }

        // GASPRICE controls execution path
        has_comparison && has_conditional && has_state_change
    }

    fn has_dynamic_gas_threshold(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let mut has_threshold_load = false;
        let mut has_comparison = false;
        let mut threshold_from_storage = false;

        // Check for threshold comparison
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => threshold_from_storage = true, // SLOAD (stored threshold)
                    0x60..=0x7f => has_threshold_load = true, // PUSH (threshold)
                    0x10 | 0x11 => has_comparison = true, // LT, GT
                    _ => {}
                }
            }
        }

        // Dynamic gas price threshold
        has_comparison && (has_threshold_load || threshold_from_storage)
    }

    fn has_ordering_assumptions(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let lookback = 30.min(pos);
        
        let mut has_coinbase_before = bytecode[pos] == 0x41;
        let mut has_prevrandao = false;
        let mut has_timestamp_check = false;
        let mut has_state_dependency = false;

        // Check for block-dependent logic (ordering sensitive)
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x42 {
                    has_timestamp_check = true; // TIMESTAMP
                }
                if bytecode[pos - offset] == 0x44 {
                    has_prevrandao = true; // PREVRANDAO
                }
            }
        }

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_state_dependency = true, // SLOAD
                    0x55 => has_state_dependency = true, // SSTORE
                    _ => {}
                }
            }
        }

        // Block properties used with state changes (ordering dependent)
        has_coinbase_before && has_state_dependency && (has_timestamp_check || has_prevrandao)
    }

    fn has_gas_refund_priority_gaming(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_gasprice = false;
        let mut has_arithmetic = false;
        let mut has_transfer = false;

        // BASEFEE with refund calculation
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x3a => has_gasprice = true, // GASPRICE
                    0x02 | 0x03 => has_arithmetic = true, // MUL, SUB (refund calc)
                    0xf1 => has_transfer = true, // CALL (refund transfer)
                    _ => {}
                }
            }
        }

        // Refund based on priority fee
        has_gasprice && has_arithmetic && has_transfer
    }
}
