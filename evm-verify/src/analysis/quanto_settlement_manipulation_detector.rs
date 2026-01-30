use serde::{Deserialize, Serialize};

/// Quanto Settlement Manipulation Detector
/// 
/// Quanto derivatives pay in one currency based on price of asset in another currency
/// Example: BTC/USD price paid in ETH
///
/// Key Attacks:
/// 1. FX rate manipulation at settlement
/// 2. Cross-currency arbitrage exploitation
/// 3. Dual price feed manipulation (asset + FX)
/// 4. Settlement currency substitution
///
/// Real-World Context:
/// - Synthetix (multi-currency synths)
/// - dYdX (cross-currency perpetuals)
/// - Potential $100M+ in quanto exposure

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantoVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct QuantoSettlementManipulationDetector {
    bytecode: Vec<u8>,
}

impl QuantoSettlementManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<QuantoVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Dual Price Feed Without Correlation Check
        if let Some(loc) = self.has_dual_price_feed_without_correlation() {
            vulnerabilities.push(QuantoVulnerability {
                vulnerability_type: "Dual Price Feed Without Correlation Check".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Quanto product uses two price feeds without correlation or consistency validation".to_string(),
                confidence: 0.85,
            });
        }

        // Pattern 2: FX Rate Manipulation Risk
        if let Some(loc) = self.has_fx_rate_manipulation_risk() {
            vulnerabilities.push(QuantoVulnerability {
                vulnerability_type: "FX Rate Manipulation at Settlement".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Settlement uses spot FX rate vulnerable to manipulation".to_string(),
                confidence: 0.80,
            });
        }

        // Pattern 3: Currency Conversion Without Slippage
        if let Some(loc) = self.has_currency_conversion_without_slippage() {
            vulnerabilities.push(QuantoVulnerability {
                vulnerability_type: "Currency Conversion Without Slippage Protection".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Cross-currency conversion lacks slippage or bounds checks".to_string(),
                confidence: 0.75,
            });
        }

        // Pattern 4: Quanto Adjustment Factor Missing
        if let Some(loc) = self.has_missing_quanto_adjustment() {
            vulnerabilities.push(QuantoVulnerability {
                vulnerability_type: "Missing Quanto Adjustment Factor".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Quanto product missing volatility/correlation adjustment factor".to_string(),
                confidence: 0.70,
            });
        }

        // Pattern 5: Settlement Currency Substitution
        if let Some(loc) = self.has_settlement_currency_substitution_risk() {
            vulnerabilities.push(QuantoVulnerability {
                vulnerability_type: "Settlement Currency Substitution Risk".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Settlement currency can be changed or manipulated".to_string(),
                confidence: 0.75,
            });
        }

        vulnerabilities
    }

    fn has_dual_price_feed_without_correlation(&self) -> Option<usize> {
        // Look for: Two STATICCALL (oracle reads) without correlation check
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0xfa { // STATICCALL (first oracle)
                let mut has_second_oracle = false;
                let mut has_correlation_check = false;

                for j in i+10..i+55.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xfa { // Second STATICCALL (second oracle)
                        has_second_oracle = true;
                        
                        // Check for correlation/consistency check (comparison)
                        for k in i..j {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT/GT
                                has_correlation_check = true;
                            }
                        }
                    }
                }

                if has_second_oracle && !has_correlation_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_fx_rate_manipulation_risk(&self) -> Option<usize> {
        // Look for: FX conversion at settlement time without TWAP
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP (settlement)
                let mut has_fx_conversion = false;
                let mut has_twap = false;

                for j in i+1..i+45.min(self.bytecode.len()) {
                    // MUL for currency conversion
                    if self.bytecode[j] == 0x02 {
                        has_fx_conversion = true;
                    }
                    // DIV suggests averaging (TWAP)
                    if self.bytecode[j] == 0x04 && has_fx_conversion {
                        // Check if multiple reads (TWAP)
                        let mut read_count = 0;
                        for k in i..j {
                            if self.bytecode[k] == 0x54 || self.bytecode[k] == 0xfa {
                                read_count += 1;
                            }
                        }
                        if read_count >= 3 {
                            has_twap = true;
                        }
                    }
                }

                if has_fx_conversion && !has_twap {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_currency_conversion_without_slippage(&self) -> Option<usize> {
        // Look for: MUL (currency conversion) without bounds check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x02 { // MUL (FX conversion)
                let mut is_conversion = false;
                let mut has_slippage_check = false;

                // Check if this is currency conversion (multiple MUL/DIV)
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV
                        is_conversion = true;
                    }
                }

                // Check for slippage protection (min/max bounds)
                for j in i..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT
                        has_slippage_check = true;
                    }
                }

                if is_conversion && !has_slippage_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_missing_quanto_adjustment(&self) -> Option<usize> {
        // Look for: Payout calculation without volatility adjustment
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Pattern: Price difference + MUL (payout) without adjustment factor
            if self.bytecode[i] == 0x03 { // SUB (price difference)
                let mut has_payout_calc = false;
                let mut has_adjustment_factor = false;

                for j in i+1..i+35.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL (calculate payout)
                        has_payout_calc = true;
                    }
                    // Adjustment factor: additional MUL with coefficient
                    if has_payout_calc && self.bytecode[j] == 0x02 && j > i+5 {
                        has_adjustment_factor = true;
                    }
                }

                // Quanto products need adjustment for correlation/volatility
                if has_payout_calc && !has_adjustment_factor {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_settlement_currency_substitution_risk(&self) -> Option<usize> {
        // Look for: Currency selection without proper validation
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP (settlement)
                let mut has_currency_selection = false;
                let mut has_validation = false;

                for j in i+1..i+35.min(self.bytecode.len()) {
                    // SLOAD that determines currency
                    if self.bytecode[j] == 0x54 {
                        has_currency_selection = true;
                    }
                    // Validation: EQ check for allowed currency
                    if self.bytecode[j] == 0x14 && has_currency_selection {
                        has_validation = true;
                    }
                }

                if has_currency_selection && !has_validation {
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
    fn test_dual_oracle_without_correlation() {
        // Two STATICCALL without correlation check
        let bytecode = vec![
            0xfa, // STATICCALL (oracle 1)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, // STATICCALL (oracle 2)
            0x02, // MUL (combine prices)
        ];
        
        let detector = QuantoSettlementManipulationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect dual oracle without correlation");
    }

    #[test]
    fn test_safe_quanto_with_correlation() {
        // Two STATICCALL with correlation check
        let bytecode = vec![
            0xfa, // STATICCALL (oracle 1)
            0x00, 0x00,
            0x11, // GT (correlation check)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, // STATICCALL (oracle 2)
        ];
        
        let detector = QuantoSettlementManipulationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        // Should have fewer issues with correlation check
        assert!(vulns.len() < 2, "Should recognize correlation protection");
    }
}
