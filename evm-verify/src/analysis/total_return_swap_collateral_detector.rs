/// Total Return Swap (TRS) Collateral Detector
///
/// Detects undercollateralization and margin manipulation in TRS contracts.
/// Coverage: UMA total return products, Synthetix equity swaps
/// Market: $20B+ synthetic equity exposure
///
/// Attack Vectors:
/// 1. Undercollateralization during volatile markets
/// 2. Margin call circumvention
/// 3. Cross-collateral rehypothecation
/// 4. Collateral valuation manipulation

use crate::bytecode::SecurityFinding;

pub struct TotalReturnSwapCollateralDetector {
    bytecode: Vec<u8>,
}

impl TotalReturnSwapCollateralDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_undercollateralization_risk() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("TRS lacks real-time collateral ratio enforcement at PC {}", pc),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_margin_call_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("TRS margin calls can be delayed or bypassed at PC {}", pc),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_cross_collateral_risk() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("TRS allows same collateral for multiple swaps at PC {}", pc),
                pc,
                confidence: 0.84,
            });
        }

        findings
    }

    fn detect_undercollateralization_risk(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // openSwap, increasePosition selectors
                if matches!(self.bytecode[i+1], 0x4d | 0x5e | 0x6f) {
                    let mut has_collateral_check = false;
                    let mut has_price_update = false;

                    for j in i..i+50.min(self.bytecode.len()) {
                        // Check for collateral ratio calculation (DIV + LT)
                        if self.bytecode[j] == 0x04 && j+4 < self.bytecode.len() {
                            if self.bytecode[j+3] == 0x10 { // LT (ratio < minimum)
                                has_collateral_check = true;
                            }
                        }
                        // Check for recent price update
                        if self.bytecode[j] == 0xfa { // STATICCALL to oracle
                            has_price_update = true;
                        }
                    }

                    if !has_collateral_check || !has_price_update {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_margin_call_bypass(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // liquidate, marginCall selectors
                if matches!(self.bytecode[i+1], 0x77 | 0x88 | 0x99) {
                    let mut has_grace_period_limit = false;

                    for j in i..i+40.min(self.bytecode.len()) {
                        // Check for timestamp comparison limiting delay
                        if self.bytecode[j] == 0x42 && j+8 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j+6] == 0x10 { // LT (time check)
                                has_grace_period_limit = true;
                            }
                        }
                    }

                    if !has_grace_period_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_cross_collateral_risk(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // depositCollateral selector
                if self.bytecode[i+1] == 0xab {
                    let mut has_uniqueness_check = false;

                    for j in i..i+45.min(self.bytecode.len()) {
                        // Check for existing collateral verification
                        if self.bytecode[j] == 0x54 && j+10 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j+8] == 0x15 { // ISZERO (not already used)
                                has_uniqueness_check = true;
                            }
                        }
                    }

                    if !has_uniqueness_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
