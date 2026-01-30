use serde::{Deserialize, Serialize};

/// Variance Swap Volatility Manipulation Detector
/// 
/// Variance swaps are derivatives where payout = (Realized Variance - Strike Variance) * Notional
/// 
/// Key Attacks:
/// 1. Price manipulation to increase realized variance
/// 2. Strategic trading at settlement to maximize variance
/// 3. Exploiting convexity in variance vs volatility
/// 4. Jump risk exploitation (sudden large price moves)
///
/// Real-World Context:
/// - Voltz Protocol (variance swaps)
/// - Deri Protocol (variance products)
/// - Potential $50M+ in variance swap TVL

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarianceSwapVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct VarianceSwapVolatilityManipulationDetector {
    bytecode: Vec<u8>,
}

impl VarianceSwapVolatilityManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VarianceSwapVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Variance Calculation Without Jump Protection
        if let Some(loc) = self.has_variance_calculation_without_jump_protection() {
            vulnerabilities.push(VarianceSwapVulnerability {
                vulnerability_type: "Variance Calculation Without Jump Protection".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Variance calculation vulnerable to large price jumps that can be manipulated".to_string(),
                confidence: 0.85,
            });
        }

        // Pattern 2: Realized Variance Settlement Gaming
        if let Some(loc) = self.has_settlement_manipulation_risk() {
            vulnerabilities.push(VarianceSwapVulnerability {
                vulnerability_type: "Settlement Period Manipulation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Settlement period vulnerable to strategic price manipulation to maximize variance".to_string(),
                confidence: 0.80,
            });
        }

        // Pattern 3: Squared Returns Without Outlier Protection
        if let Some(loc) = self.has_squared_returns_without_outlier_protection() {
            vulnerabilities.push(VarianceSwapVulnerability {
                vulnerability_type: "Unprotected Squared Returns".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Squared returns calculation amplifies manipulation impact without outlier filtering".to_string(),
                confidence: 0.75,
            });
        }

        // Pattern 4: Strike Variance vs Realized Variance Comparison
        if let Some(loc) = self.has_unsafe_variance_comparison() {
            vulnerabilities.push(VarianceSwapVulnerability {
                vulnerability_type: "Unsafe Variance Comparison".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Variance comparison vulnerable to precision loss or manipulation".to_string(),
                confidence: 0.70,
            });
        }

        // Pattern 5: Sampling Frequency Manipulation
        if let Some(loc) = self.has_sampling_frequency_vulnerability() {
            vulnerabilities.push(VarianceSwapVulnerability {
                vulnerability_type: "Sampling Frequency Vulnerability".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Price sampling frequency can be manipulated to affect realized variance".to_string(),
                confidence: 0.75,
            });
        }

        vulnerabilities
    }

    fn has_variance_calculation_without_jump_protection(&self) -> Option<usize> {
        // Look for: MUL (squaring) + DIV (variance calc) without bounds check
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x02 { // MUL (for squared returns)
                let mut has_another_mul = false;
                let mut has_cap_check = false;

                // Check for variance formula: sum of squared returns
                for j in i+1..i+30.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // Another MUL (confirms squaring)
                        has_another_mul = true;
                    }
                    // Look for cap/max check to prevent jump exploitation
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT
                        has_cap_check = true;
                    }
                }

                if has_another_mul && !has_cap_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_settlement_manipulation_risk(&self) -> Option<usize> {
        // Look for: TIMESTAMP + price operations near settlement
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let mut has_price_read = false;
                let mut has_variance_calc = false;

                for j in i+1..i+40.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // SLOAD (price read)
                        has_price_read = true;
                    }
                    if self.bytecode[j] == 0x02 { // MUL (variance calc)
                        has_variance_calc = true;
                    }
                }

                // Settlement time with variance calculation = manipulation risk
                if has_price_read && has_variance_calc {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_squared_returns_without_outlier_protection(&self) -> Option<usize> {
        // Look for: (Price2 - Price1)^2 without outlier filtering
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Pattern: SUB (return) + MUL (squaring)
            if self.bytecode[i] == 0x03 { // SUB (calculate return)
                for j in i+1..i+10.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL (square the return)
                        // Check if there's outlier protection (max check)
                        let mut has_outlier_filter = false;
                        for k in i..j {
                            if self.bytecode[k] == 0x11 { // GT (outlier check)
                                has_outlier_filter = true;
                            }
                        }
                        if !has_outlier_filter {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_unsafe_variance_comparison(&self) -> Option<usize> {
        // Look for: Variance comparison for payout without proper checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Pattern: Multiple MUL (variance calc) + SUB (strike - realized)
            let mut mul_count = 0;
            let mut has_sub = false;
            let mut has_overflow_check = false;

            for j in i..i+25.min(self.bytecode.len()) {
                if self.bytecode[j] == 0x02 {
                    mul_count += 1;
                }
                if self.bytecode[j] == 0x03 {
                    has_sub = true;
                }
                if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {
                    has_overflow_check = true;
                }
            }

            // Variance comparison without overflow protection
            if mul_count >= 2 && has_sub && !has_overflow_check {
                return Some(i);
            }
        }
        None
    }

    fn has_sampling_frequency_vulnerability(&self) -> Option<usize> {
        // Look for: Time-based sampling without frequency validation
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let mut has_interval_calc = false;
                let mut has_interval_check = false;

                for j in i+1..i+35.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x03 || self.bytecode[j] == 0x04 { // SUB/DIV (interval)
                        has_interval_calc = true;
                    }
                    // Check for minimum interval enforcement
                    if self.bytecode[j] == 0x10 && has_interval_calc { // LT after interval calc
                        has_interval_check = true;
                    }
                }

                // Sampling without frequency validation
                if has_interval_calc && !has_interval_check {
                    return Some(i);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variance_without_jump_protection() {
        // Bytecode: MUL, MUL (squared returns without cap)
        let bytecode = vec![
            0x02, // MUL (square)
            0x01, // ADD
            0x02, // MUL (square again)
            0x04, // DIV (calc variance)
        ];
        
        let detector = VarianceSwapVolatilityManipulationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect unprotected variance calculation");
    }

    #[test]
    fn test_safe_variance_with_caps() {
        // Bytecode: MUL with GT check (capped squared returns)
        let bytecode = vec![
            0x02, // MUL
            0x11, // GT (cap check)
            0x57, // JUMPI
            0x02, // MUL
        ];
        
        let detector = VarianceSwapVolatilityManipulationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert_eq!(vulns.len(), 0, "Should not flag protected variance");
    }
}
