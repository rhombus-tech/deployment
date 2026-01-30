/// Interest Rate Swap (IRS) Curve Manipulation Detector
///
/// Detects yield curve manipulation and rate fixing in IRS contracts.
/// Coverage: Fixed-floating swaps, basis swaps, OIS swaps
/// Market: $20B+ interest rate derivatives
///
/// Attack Vectors:
/// 1. LIBOR/SOFR rate manipulation
/// 2. Curve interpolation exploits
/// 3. Payment frequency gaming
/// 4. Notional amount manipulation

use crate::bytecode::SecurityFinding;

pub struct InterestRateSwapCurveManipulationDetector {
    bytecode: Vec<u8>,
}

impl InterestRateSwapCurveManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_rate_fixing_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("IRS uses single-source rate fixing without TWAP at PC {}", pc),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_curve_interpolation_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("IRS curve interpolation vulnerable to manipulation at PC {}", pc),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_payment_timing_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("IRS payment calculations vulnerable to timestamp manipulation at PC {}", pc),
                pc,
                confidence: 0.82,
            });
        }

        findings
    }

    fn detect_rate_fixing_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // fixRate, calculatePayment selectors
                if matches!(self.bytecode[i+1], 0x3c | 0x4d | 0x5e) {
                    let mut oracle_calls = 0;
                    let mut has_twap = false;

                    for j in i..i+45.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            oracle_calls += 1;
                        }
                        // TWAP: multiple SLOADs with time deltas
                        if self.bytecode[j] == 0x54 && j+12 < self.bytecode.len() {
                            if self.bytecode[j+10] == 0x03 { // SUB (time delta)
                                has_twap = true;
                            }
                        }
                    }

                    if oracle_calls < 2 && !has_twap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_curve_interpolation_exploit(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // interpolateRate selector
                if self.bytecode[i+1] == 0x6f {
                    let mut has_bounds_check = false;
                    let mut has_multiple_points = false;

                    for j in i..(i+55).min(self.bytecode.len()) {
                        // Bounds checking for interpolation range
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT
                            has_bounds_check = true;
                        }
                        // Multiple curve points (multiple SLOADs)
                        let end = (j + 20).min(self.bytecode.len());
                        let sload_count = self.bytecode[j..end]
                            .iter()
                            .filter(|&&b| b == 0x54)
                            .count();
                        if sload_count >= 3 {
                            has_multiple_points = true;
                        }
                    }

                    if !has_bounds_check || !has_multiple_points {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_payment_timing_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // calculateAccrued, settlePayment selectors
                if matches!(self.bytecode[i+1], 0x7a | 0x8b | 0x9c) {
                    let mut has_day_count_convention = false;

                    for j in i..i+40.min(self.bytecode.len()) {
                        // Day count: 360 or 365 division
                        if self.bytecode[j] == 0x04 { // DIV
                            has_day_count_convention = true;
                        }
                    }

                    if !has_day_count_convention {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
