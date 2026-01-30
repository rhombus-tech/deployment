use serde::{Deserialize, Serialize};

/// Digital/Binary Option Delta Discontinuity Detector
/// 
/// Digital options have discontinuous payoffs: 0 below strike, fixed payout above strike
/// This creates infinite delta at the strike price, enabling manipulation
///
/// Key Attacks:
/// 1. Price pinning at strike to maximize delta risk
/// 2. Sudden price moves across strike for asymmetric profit
/// 3. Market maker exposure to discontinuous greeks
/// 4. Settlement manipulation at strike boundary
///
/// Real-World Context:
/// - Thales (binary options protocol)
/// - BinaryX
/// - Potential $20M+ in binary options TVL

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalOptionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DigitalOptionDeltaDiscontinuityDetector {
    bytecode: Vec<u8>,
}

impl DigitalOptionDeltaDiscontinuityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DigitalOptionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Binary Payoff Without Strike Buffer
        if let Some(loc) = self.has_binary_payoff_without_buffer() {
            vulnerabilities.push(DigitalOptionVulnerability {
                vulnerability_type: "Binary Payoff Without Strike Buffer".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Binary option settles exactly at strike without buffer, enabling precise manipulation".to_string(),
                confidence: 0.85,
            });
        }

        // Pattern 2: Strike Price Pinning Vulnerability
        if let Some(loc) = self.has_strike_pinning_risk() {
            vulnerabilities.push(DigitalOptionVulnerability {
                vulnerability_type: "Strike Price Pinning Risk".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Strike price can be pinned to maximize market maker losses".to_string(),
                confidence: 0.80,
            });
        }

        // Pattern 3: Delta Hedging Near Strike
        if let Some(loc) = self.has_unsafe_delta_hedging() {
            vulnerabilities.push(DigitalOptionVulnerability {
                vulnerability_type: "Unsafe Delta Hedging Near Strike".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Delta hedging breaks down near strike due to discontinuity".to_string(),
                confidence: 0.75,
            });
        }

        // Pattern 4: Settlement Without TWAP
        if let Some(loc) = self.has_spot_settlement_risk() {
            vulnerabilities.push(DigitalOptionVulnerability {
                vulnerability_type: "Spot Settlement Without TWAP".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Binary option settles on spot price without TWAP, enabling last-moment manipulation".to_string(),
                confidence: 0.90,
            });
        }

        // Pattern 5: Discontinuous Payout Function
        if let Some(loc) = self.has_discontinuous_payout_without_smoothing() {
            vulnerabilities.push(DigitalOptionVulnerability {
                vulnerability_type: "Discontinuous Payout Without Smoothing".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Payout function is discontinuous without smoothing mechanism".to_string(),
                confidence: 0.70,
            });
        }

        vulnerabilities
    }

    fn has_binary_payoff_without_buffer(&self) -> Option<usize> {
        // Look for: if (price > strike) then payout, without buffer zone
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Pattern: GT/LT (price comparison) + JUMPI + fixed payout
            if self.bytecode[i] == 0x11 || self.bytecode[i] == 0x10 { // GT/LT
                if let Some(&0x57) = self.bytecode.get(i+1) { // JUMPI (binary branch)
                    // Check if there's a buffer check (additional GT/LT nearby)
                    let mut has_buffer = false;
                    for j in i+2..i+15.min(self.bytecode.len()) {
                        if (self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10) &&
                           j != i { // Another comparison = buffer
                            has_buffer = true;
                        }
                    }
                    
                    if !has_buffer {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_strike_pinning_risk(&self) -> Option<usize> {
        // Look for: Settlement logic that can be pinned at strike
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP (settlement time)
                let mut has_price_check = false;
                let mut has_anti_pin_protection = false;

                for j in i+1..i+45.min(self.bytecode.len()) {
                    // Price comparison at settlement
                    if self.bytecode[j] == 0x14 { // EQ (exact strike comparison)
                        has_price_check = true;
                    }
                    // Anti-pinning: multiple price samples or time-weighted
                    if self.bytecode[j] == 0x04 && has_price_check { // DIV (averaging)
                        has_anti_pin_protection = true;
                    }
                }

                if has_price_check && !has_anti_pin_protection {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_unsafe_delta_hedging(&self) -> Option<usize> {
        // Look for: Delta calculation near binary option strike
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Pattern: Price difference (SUB) + DIV (delta calc)
            if self.bytecode[i] == 0x03 { // SUB (price - strike)
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV (delta calculation)
                        // Check if there's discontinuity handling
                        let mut has_discontinuity_check = false;
                        for k in i..j {
                            // Absolute value or min check to handle discontinuity
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 {
                                has_discontinuity_check = true;
                            }
                        }
                        if !has_discontinuity_check {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_spot_settlement_risk(&self) -> Option<usize> {
        // Look for: Settlement using spot price without time-weighting
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let mut has_settlement = false;
                let mut has_twap = false;

                for j in i+1..i+35.min(self.bytecode.len()) {
                    // Settlement logic (comparison + payout)
                    if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10 {
                        has_settlement = true;
                    }
                    // TWAP check: multiple SLOAD + DIV pattern
                    if self.bytecode[j] == 0x04 && has_settlement {
                        // Check for multiple price reads (TWAP)
                        let mut sload_count = 0;
                        for k in i..j {
                            if self.bytecode[k] == 0x54 {
                                sload_count += 1;
                            }
                        }
                        if sload_count >= 2 {
                            has_twap = true;
                        }
                    }
                }

                if has_settlement && !has_twap {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_discontinuous_payout_without_smoothing(&self) -> Option<usize> {
        // Look for: Step function payout without smoothing
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Pattern: JUMPI (discontinuous branch) with different payouts
            if self.bytecode[i] == 0x57 { // JUMPI
                let mut has_payout_a = false;
                let mut has_payout_b = false;
                let mut has_smoothing = false;

                // Check both branches have different payouts
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x60 { // PUSH1 (payout value)
                        if !has_payout_a {
                            has_payout_a = true;
                        } else {
                            has_payout_b = true;
                        }
                    }
                    // Smoothing: gradual transition using MUL/DIV
                    if self.bytecode[j] == 0x02 && self.bytecode.get(j+2) == Some(&0x04) {
                        has_smoothing = true;
                    }
                }

                if has_payout_a && has_payout_b && !has_smoothing {
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
    fn test_binary_payoff_without_buffer() {
        // Bytecode: GT + JUMPI (binary decision without buffer)
        let bytecode = vec![
            0x11, // GT (price > strike)
            0x57, // JUMPI (binary branch)
            0x60, 0x0a, // PUSH1 10 (payout)
        ];
        
        let detector = DigitalOptionDeltaDiscontinuityDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect binary payoff without buffer");
    }

    #[test]
    fn test_safe_binary_with_buffer() {
        // Bytecode: GT + another GT (buffer zone)
        let bytecode = vec![
            0x11, // GT (price > strike - buffer)
            0x57, // JUMPI
            0x11, // GT (price > strike + buffer)
            0x57, // JUMPI
        ];
        
        let detector = DigitalOptionDeltaDiscontinuityDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        // Should have fewer or different vulnerabilities
        assert!(vulns.len() < 2, "Should recognize buffer protection");
    }
}
