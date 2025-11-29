// Math Edge Case Detector
// Detects sophisticated mathematical vulnerabilities and rounding issues

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MathEdgeCaseVulnerability {
    pub vulnerability_type: MathEdgeCaseType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub edge_case_values: Vec<EdgeCaseValue>,
    pub expected_loss: u128,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MathEdgeCaseType {
    RoundingError,              // Loss due to integer division
    PrecisionLoss,              // Accumulated rounding errors
    DivisionByZero,             // Unchecked division
    OverflowInMultiplication,   // a * b before a / b
    UnderflowInSubtraction,     // a - b where b > a
    ModuloZero,                 // x % 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeCaseValue {
    pub input: String,
    pub expected_output: String,
    pub actual_output: String,
    pub loss_amount: u128,
}

pub struct MathEdgeCaseDetector {
    bytecode: Vec<u8>,
}

impl MathEdgeCaseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn analyze(&self) -> Vec<MathEdgeCaseVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_rounding_errors());
        vulnerabilities.extend(self.detect_division_by_zero());
        vulnerabilities.extend(self.detect_overflow_in_mul_div());
        vulnerabilities.extend(self.detect_precision_loss());

        vulnerabilities
    }

    fn detect_rounding_errors(&self) -> Vec<MathEdgeCaseVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: MUL followed immediately by DIV (a * b / c)
        // Problem: Small values of 'a' result in 0 after division
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x02 && self.bytecode[i + 2] == 0x04 {  // MUL then DIV
                vulns.push(MathEdgeCaseVulnerability {
                    vulnerability_type: MathEdgeCaseType::RoundingError,
                    severity: SecuritySeverity::Medium,
                    description: "Integer division causes rounding loss - users lose fractional amounts".to_string(),
                    edge_case_values: vec![
                        EdgeCaseValue {
                            input: "amount = 1, fee = 100, basis = 10000".to_string(),
                            expected_output: "0.01 fee".to_string(),
                            actual_output: "0 fee (rounded down)".to_string(),
                            loss_amount: 10_000_000_000_000u128, // Loss per transaction
                        },
                        EdgeCaseValue {
                            input: "amount = 50, fee = 100, basis = 10000".to_string(),
                            expected_output: "0.5 fee".to_string(),
                            actual_output: "0 fee (rounded down)".to_string(),
                            loss_amount: 500_000_000_000_000u128,
                        },
                    ],
                    expected_loss: 1_000_000_000_000_000_000u128, // $1M over time
                    remediation: "Use higher precision: (amount * fee * 1e18) / basis / 1e18 or check for zero result".to_string(),
                });
            }
        }

        vulns
    }

    fn detect_division_by_zero(&self) -> Vec<MathEdgeCaseVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: DIV without prior zero check
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x04 {  // DIV
                // Check if there's an ISZERO check before
                if !self.has_zero_check_before(i, 10) {
                    vulns.push(MathEdgeCaseVulnerability {
                        vulnerability_type: MathEdgeCaseType::DivisionByZero,
                        severity: SecuritySeverity::High,
                        description: "Division without zero check - contract will revert unexpectedly".to_string(),
                        edge_case_values: vec![
                            EdgeCaseValue {
                                input: "divisor = 0".to_string(),
                                expected_output: "graceful error or default".to_string(),
                                actual_output: "REVERT (DOS)".to_string(),
                                loss_amount: 0,
                            },
                        ],
                        expected_loss: 0, // DOS not fund loss
                        remediation: "Add: require(divisor != 0) before division".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn detect_overflow_in_mul_div(&self) -> Vec<MathEdgeCaseVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: (a * b) / c where a * b can overflow
        // Should be: (a / c) * b or use checked math
        for i in 0..self.bytecode.len().saturating_sub(6) {
            if self.bytecode[i] == 0x02 {  // MUL
                // Check if values are large (PUSH32 before)
                if self.has_large_constant_before(i, 5) {
                    vulns.push(MathEdgeCaseVulnerability {
                        vulnerability_type: MathEdgeCaseType::OverflowInMultiplication,
                        severity: SecuritySeverity::High,
                        description: "Multiplication before division can overflow even if final result is valid".to_string(),
                        edge_case_values: vec![
                            EdgeCaseValue {
                                input: "a = 2^255, b = 2, c = 4".to_string(),
                                expected_output: "2^254 (valid)".to_string(),
                                actual_output: "OVERFLOW (a*b overflows uint256)".to_string(),
                                loss_amount: 10_000_000_000_000_000_000_000u128,
                            },
                        ],
                        expected_loss: 10_000_000_000_000_000_000_000u128,
                        remediation: "Reorder: (a / c) * b or use mulDiv with 512-bit intermediate".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn detect_precision_loss(&self) -> Vec<MathEdgeCaseVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Multiple sequential divisions (compounds rounding)
        let mut div_count = 0;
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x04 {  // DIV
                div_count += 1;
                // Check for another DIV within 20 bytes
                if self.has_div_in_range(i + 1, i + 20) {
                    div_count += 1;
                }
            }
        }

        if div_count >= 2 {
            vulns.push(MathEdgeCaseVulnerability {
                vulnerability_type: MathEdgeCaseType::PrecisionLoss,
                severity: SecuritySeverity::Medium,
                description: format!("Multiple divisions ({}) compound rounding errors", div_count),
                edge_case_values: vec![
                    EdgeCaseValue {
                        input: "amount = 1000".to_string(),
                        expected_output: "990 (1% loss)".to_string(),
                        actual_output: "980 (2% loss from compound rounding)".to_string(),
                        loss_amount: 10_000_000_000_000_000_000u128,
                    },
                ],
                expected_loss: 100_000_000_000_000_000_000u128,
                remediation: "Defer division to end: (a * b * c) / (d * e) instead of (a/d) * (b/e) * c".to_string(),
            });
        }

        vulns
    }

    // === HELPER METHODS ===

    fn has_zero_check_before(&self, offset: usize, range: usize) -> bool {
        let start = offset.saturating_sub(range);
        for i in start..offset {
            if i < self.bytecode.len() && self.bytecode[i] == 0x15 {  // ISZERO
                return true;
            }
        }
        false
    }

    fn has_large_constant_before(&self, offset: usize, range: usize) -> bool {
        let start = offset.saturating_sub(range);
        for i in start..offset {
            if i < self.bytecode.len() && self.bytecode[i] == 0x7F {  // PUSH32 (large value)
                return true;
            }
        }
        false
    }

    fn has_div_in_range(&self, start: usize, end: usize) -> bool {
        for i in start..end.min(self.bytecode.len()) {
            if self.bytecode[i] == 0x04 {
                return true;
            }
        }
        false
    }
}

/// Calculate total expected loss from math edge cases
pub fn calculate_math_risk(vulnerabilities: &[MathEdgeCaseVulnerability]) -> MathRiskReport {
    let total_loss: u128 = vulnerabilities.iter()
        .map(|v| v.expected_loss)
        .sum();

    let critical_count = vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();

    MathRiskReport {
        total_vulnerabilities: vulnerabilities.len(),
        critical_count,
        expected_annual_loss: total_loss,
        risk_level: if total_loss > 10_000_000_000_000_000_000_000u128 {
            "CRITICAL - Systematic value leakage".to_string()
        } else if total_loss > 1_000_000_000_000_000_000_000u128 {
            "HIGH - Significant precision loss".to_string()
        } else {
            "MEDIUM - Minor rounding issues".to_string()
        },
        recommendation: if critical_count > 0 {
            "URGENT: Fix division by zero and overflow issues immediately".to_string()
        } else {
            "Review all math operations for edge cases and add precision".to_string()
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MathRiskReport {
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub expected_annual_loss: u128,
    pub risk_level: String,
    pub recommendation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rounding_error_detection() {
        // MUL followed by DIV
        let bytecode = vec![
            0x02,  // MUL
            0x60, 0x00,  // PUSH1 0
            0x04,  // DIV
        ];
        
        let detector = MathEdgeCaseDetector::new(bytecode);
        let vulns = detector.detect_rounding_errors();
        
        assert!(vulns.len() > 0, "Should detect rounding error");
    }

    #[test]
    fn test_division_by_zero() {
        // DIV without ISZERO check
        let bytecode = vec![
            0x60, 0x00,  // PUSH1 0
            0x04,  // DIV (no zero check before)
        ];
        
        let detector = MathEdgeCaseDetector::new(bytecode);
        let vulns = detector.detect_division_by_zero();
        
        assert!(vulns.len() > 0, "Should detect division by zero risk");
    }
}
