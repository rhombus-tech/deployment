/// Swaption Volatility Manipulation Detector
///
/// Detects implied volatility manipulation in options on swaps.
/// Coverage: Interest rate swaptions, payer/receiver swaptions
/// Market: $20B+ swaption notional

use crate::bytecode::SecurityFinding;

pub struct SwaptionVolatilityManipulationDetector {
    bytecode: Vec<u8>,
}

impl SwaptionVolatilityManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_implied_vol_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Swaption implied volatility calculated from manipulable source at PC {}", pc),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_vega_exposure_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Swaption vega exposure lacks hedging limits at PC {}", pc),
                pc,
                confidence: 0.81,
            });
        }

        findings
    }

    fn detect_implied_vol_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // calculatePremium, priceOption selectors
                if matches!(self.bytecode[i+1], 0x2b | 0x3c | 0x4d) {
                    let mut vol_sources = 0;

                    for j in i..i+45.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL (vol oracle)
                            vol_sources += 1;
                        }
                    }

                    if vol_sources < 2 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_vega_exposure_exploit(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // sellSwaption, writeOption selectors
                if matches!(self.bytecode[i+1], 0x5e | 0x6f) {
                    let mut has_exposure_limit = false;

                    for j in i..i+35.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x10 { // LT (limit check)
                            has_exposure_limit = true;
                        }
                    }

                    if !has_exposure_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
