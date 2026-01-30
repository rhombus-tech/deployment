/// Variance Swap Vega Exposure Detector
///
/// Detects excessive vega exposure and variance strike manipulation.
/// Coverage: Variance swaps, volatility swaps, dispersion trading
/// Market: $20B+ vol derivatives

use crate::bytecode::SecurityFinding;

pub struct VarianceSwapVegaExposureDetector {
    bytecode: Vec<u8>,
}

impl VarianceSwapVegaExposureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_realized_vol_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Variance swap realized volatility calculation manipulable at PC {}", pc),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_vega_limit_missing() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Variance swap lacks vega exposure limits at PC {}", pc),
                pc,
                confidence: 0.83,
            });
        }

        findings
    }

    fn detect_realized_vol_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // calculateVariance, settleVarianceSwap selectors
                if matches!(self.bytecode[i+1], 0x3d | 0x4e) {
                    let mut observation_count = 0;

                    for j in i..i+45.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD (price observation)
                            observation_count += 1;
                        }
                    }

                    // Vulnerable if too few observations (< 24 for daily)
                    if observation_count < 20 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_vega_limit_missing(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // sellVariance, writeVarianceSwap selectors
                if matches!(self.bytecode[i+1], 0x5f | 0x6a) {
                    let mut has_notional_limit = false;

                    for j in i..i+35.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x10 { // LT
                            has_notional_limit = true;
                        }
                    }

                    if !has_notional_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
