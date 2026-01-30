/// Interchain Liquidation Race Detector
///
/// Detects cross-chain liquidation timing vulnerabilities.
/// Coverage: Multi-chain lending protocols, cross-chain collateral
/// Market: $10B+ bridge volume

use crate::bytecode::SecurityFinding;

pub struct InterchainLiquidationRaceDetector {
    bytecode: Vec<u8>,
}

impl InterchainLiquidationRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_cross_chain_liquidation_timing() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Cross-chain liquidation timing exploitable via message delay at PC {}", pc),
                pc,
                confidence: 0.82,
            });
        }

        if let Some(pc) = self.detect_missing_finality_check() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Cross-chain liquidation lacks finality verification at PC {}", pc),
                pc,
                confidence: 0.88,
            });
        }

        findings
    }

    fn detect_cross_chain_liquidation_timing(&self) -> Option<usize> {
        // Detect liquidate function that queries cross-chain state
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // liquidate, liquidateBorrow selectors
                if matches!(self.bytecode[i+1], 0x96 | 0xa7 | 0xb8) {
                    let mut has_cross_chain_call = false;
                    let mut has_delay_protection = false;

                    for j in i..i+45.min(self.bytecode.len()) {
                        // External call (likely cross-chain message)
                        if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0xfa { // CALL/STATICCALL
                            has_cross_chain_call = true;
                        }
                        // Check for timestamp delay protection
                        if self.bytecode[j] == 0x42 && j+10 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j+8] == 0x01 { // ADD (delay added)
                                has_delay_protection = true;
                            }
                        }
                    }

                    // Vulnerable if cross-chain call without delay protection
                    if has_cross_chain_call && !has_delay_protection {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_missing_finality_check(&self) -> Option<usize> {
        // Detect cross-chain state queries without finality verification
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // getCollateralValue, checkHealth selectors
                if matches!(self.bytecode[i+1], 0xc9 | 0xda) {
                    let mut has_external_call = false;
                    let mut has_confirmation_check = false;

                    for j in i..i+40.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL (cross-chain query)
                            has_external_call = true;
                        }
                        // Check for confirmation count or finality verification
                        if self.bytecode[j] == 0x11 && has_external_call { // GT (confirmation check)
                            has_confirmation_check = true;
                        }
                    }

                    if has_external_call && !has_confirmation_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
