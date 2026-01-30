use serde::{Serialize, Deserialize};
use crate::bytecode::SecurityFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GasTokenArbitrageVulnerability {
    PatternDetected,
    SecurityIssue,
}

pub struct GasTokenArbitrageDetector {
    bytecode: Vec<u8>,
}

impl GasTokenArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_gas_token_minting_arbitrage() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Gas token minting vulnerable to arbitrage exploitation at PC {}. \
                    Predictable gas price patterns enable profitable arbitrage.",
                    pc
                ),
                pc,
                confidence: 0.84,
            });
        }

        if let Some(pc) = self.detect_chi_gst2_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "CHI/GST2 gas token mechanism exploitable at PC {}. \
                    Flash loan attacks can manipulate gas token economics.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_gas_price_oracle_dependency() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Gas token pricing relies on manipulable oracle at PC {}. \
                    Attacker can exploit mispriced gas token conversions.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        findings
    }

    fn detect_gas_token_minting_arbitrage(&self) -> Option<usize> {
        // Look for gas token minting patterns (CHI, GST2) with predictable conditions
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // mint, free, freeUpTo selectors (gas token patterns)
                if matches!(selector, [0x40, 0xc1, 0x0f, 0x19] | [0xd8, 0xdf, 0xee, 0xb6] | [0x63, 0xd9, 0x84, 0xe8]) {
                    let mut uses_gasprice = false;
                    let mut has_profitability_check = false;
                    let mut creates_storage = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for GASPRICE opcode
                        if self.bytecode[j] == 0x3a { // GASPRICE
                            uses_gasprice = true;
                        }
                        // Check for profitability calculation
                        if j + 8 < self.bytecode.len() {
                            let mut has_cost_calc = false;
                            let mut has_threshold = false;
                            for k in j..j + 8 {
                                if self.bytecode[k] == 0x02 || self.bytecode[k] == 0x04 { // MUL or DIV
                                    has_cost_calc = true;
                                }
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                    has_threshold = true;
                                }
                            }
                            if has_cost_calc && has_threshold {
                                has_profitability_check = true;
                            }
                        }
                        // Check for storage slot creation (SSTORE)
                        if self.bytecode[j] == 0x55 { // SSTORE
                            creates_storage = true;
                        }
                    }
                    
                    if uses_gasprice && creates_storage && !has_profitability_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_chi_gst2_manipulation(&self) -> Option<usize> {
        // Look for CHI/GST2 specific patterns with flash loan vulnerability
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // freeUpTo, freeFrom selectors
                if matches!(selector, [0x63, 0xd9, 0x84, 0xe8] | [0x79, 0x92, 0x86, 0xf9]) {
                    let mut destroys_tokens = false;
                    let mut refunds_gas = false;
                    let mut has_reentrancy_guard = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for SELFDESTRUCT (gas token burning)
                        if self.bytecode[j] == 0xff { // SELFDESTRUCT
                            destroys_tokens = true;
                        }
                        // Check for gas refund mechanism
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j] == 0x3a && // GASPRICE
                               j + 2 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x02 { // MUL (calculating refund)
                                refunds_gas = true;
                            }
                        }
                        // Check for reentrancy guard
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x15 && // ISZERO
                               self.bytecode[j + 3] == 0x57 { // JUMPI (guard check)
                                has_reentrancy_guard = true;
                            }
                        }
                    }
                    
                    if destroys_tokens && refunds_gas && !has_reentrancy_guard {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_gas_price_oracle_dependency(&self) -> Option<usize> {
        // Look for gas token operations relying on external price oracles
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // getGasPrice, calculateValue selectors
                if matches!(selector, [0xa8, 0x4f, _, _] | [0xb9, 0x6e, _, _]) {
                    let mut has_external_call = false;
                    let mut has_twap = false;
                    let mut uses_gasprice_directly = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for external oracle call
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0xfa || self.bytecode[j] == 0xf1 { // STATICCALL or CALL
                                has_external_call = true;
                            }
                        }
                        // Check for TWAP calculation
                        if j + 10 < self.bytecode.len() {
                            let mut has_timestamp = false;
                            let mut has_accumulator = false;
                            for k in j..j + 10 {
                                if self.bytecode[k] == 0x42 { // TIMESTAMP
                                    has_timestamp = true;
                                }
                                if self.bytecode[k] == 0x02 || self.bytecode[k] == 0x04 { // MUL or DIV
                                    has_accumulator = true;
                                }
                            }
                            if has_timestamp && has_accumulator {
                                has_twap = true;
                            }
                        }
                        // Check for direct GASPRICE usage
                        if self.bytecode[j] == 0x3a { // GASPRICE
                            uses_gasprice_directly = true;
                        }
                    }
                    
                    if (has_external_call || uses_gasprice_directly) && !has_twap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GasTokenArbitrageVulnerability> {
        self.detect().into_iter().map(|_| GasTokenArbitrageVulnerability::SecurityIssue).collect()
    }
}
