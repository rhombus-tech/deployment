use serde::{Deserialize, Serialize};

/// Binary Option Price Pinning Detector
/// 
/// Price pinning: Manipulating spot price to stay exactly at option strike at expiry
/// to maximize losses for option sellers or market makers
///
/// Key Attacks:
/// 1. Pin price at strike to maximize gamma exposure
/// 2. Max pain strategy - pin at strike with most open interest
/// 3. Last-minute manipulation right before settlement
/// 4. Coordinated pinning across multiple strikes
///
/// Real-World Context:
/// - Traditional options: "Max Pain Theory"
/// - DeFi Binary Options: Thales, BinaryX
/// - Impact: $10M+ potential manipulation per event

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryOptionPinningVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BinaryOptionPricePinningDetector {
    bytecode: Vec<u8>,
}

impl BinaryOptionPricePinningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BinaryOptionPinningVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Settlement at Exact Strike Without Tolerance
        if let Some(loc) = self.has_exact_strike_settlement() {
            vulnerabilities.push(BinaryOptionPinningVulnerability {
                vulnerability_type: "Exact Strike Settlement".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Binary option settles at exact strike price without tolerance band, enabling precise pinning".to_string(),
                confidence: 0.90,
            });
        }

        // Pattern 2: Single Block Settlement Window
        if let Some(loc) = self.has_single_block_settlement() {
            vulnerabilities.push(BinaryOptionPinningVulnerability {
                vulnerability_type: "Single Block Settlement Window".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Settlement occurs in single block, allowing last-block manipulation".to_string(),
                confidence: 0.85,
            });
        }

        // Pattern 3: No Anti-Pinning Mechanism
        if let Some(loc) = self.has_no_anti_pinning_protection() {
            vulnerabilities.push(BinaryOptionPinningVulnerability {
                vulnerability_type: "No Anti-Pinning Protection".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Missing anti-pinning mechanisms like TWAP or random settlement timing".to_string(),
                confidence: 0.75,
            });
        }

        // Pattern 4: Open Interest Concentration Risk
        if let Some(loc) = self.has_open_interest_concentration_risk() {
            vulnerabilities.push(BinaryOptionPinningVulnerability {
                vulnerability_type: "Open Interest Concentration Risk".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "High open interest at single strike creates pinning incentive".to_string(),
                confidence: 0.70,
            });
        }

        // Pattern 5: Predictable Settlement Time
        if let Some(loc) = self.has_predictable_settlement_time() {
            vulnerabilities.push(BinaryOptionPinningVulnerability {
                vulnerability_type: "Predictable Settlement Time".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Settlement time is predictable, allowing attackers to time manipulation perfectly".to_string(),
                confidence: 0.80,
            });
        }

        vulnerabilities
    }

    fn has_exact_strike_settlement(&self) -> Option<usize> {
        // Look for: EQ comparison (exact strike) at settlement
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x14 { // EQ (exact comparison)
                // Check if this is settlement logic (near TIMESTAMP)
                let mut is_settlement = false;
                let mut has_tolerance = false;

                for j in i.saturating_sub(20)..i {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        is_settlement = true;
                    }
                }

                // Check for tolerance band (additional GT/LT around EQ)
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {
                        has_tolerance = true;
                    }
                }

                if is_settlement && !has_tolerance {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_single_block_settlement(&self) -> Option<usize> {
        // Look for: Settlement window without multi-block averaging
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let mut has_settlement_logic = false;
                let mut has_multi_block = false;

                for j in i+1..i+35.min(self.bytecode.len()) {
                    // Settlement: comparison + payout
                    if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10 {
                        has_settlement_logic = true;
                    }
                    // Multi-block: DIV suggests averaging across blocks
                    if self.bytecode[j] == 0x04 && has_settlement_logic {
                        // Check for multiple price reads
                        let mut sload_count = 0;
                        for k in i..j {
                            if self.bytecode[k] == 0x54 { // SLOAD (price read)
                                sload_count += 1;
                            }
                        }
                        if sload_count >= 3 {
                            has_multi_block = true;
                        }
                    }
                }

                if has_settlement_logic && !has_multi_block {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_no_anti_pinning_protection(&self) -> Option<usize> {
        // Look for: Strike comparison without TWAP or randomness
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Strike comparison
            if self.bytecode[i] == 0x11 || self.bytecode[i] == 0x10 { // GT/LT
                let mut is_option_logic = false;
                let mut has_twap = false;
                let mut has_randomness = false;

                // Check if binary option (JUMPI for binary payout)
                for j in i+1..i+10.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x57 { // JUMPI
                        is_option_logic = true;
                    }
                }

                // Check for anti-pinning: TWAP (multiple reads + DIV)
                for j in i.saturating_sub(30)..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV (averaging)
                        let mut read_count = 0;
                        for k in i.saturating_sub(30)..j {
                            if self.bytecode[k] == 0x54 {
                                read_count += 1;
                            }
                        }
                        if read_count >= 2 {
                            has_twap = true;
                        }
                    }
                    // Randomness: BLOCKHASH or VRF call
                    if self.bytecode[j] == 0x40 || self.bytecode[j] == 0xfa {
                        has_randomness = true;
                    }
                }

                if is_option_logic && !has_twap && !has_randomness {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_open_interest_concentration_risk(&self) -> Option<usize> {
        // Look for: Open interest tracking without concentration limits
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Pattern: SSTORE (update open interest) without cap check
            if self.bytecode[i] == 0x55 { // SSTORE
                let mut is_open_interest = false;
                let mut has_cap = false;

                // Check if tracking open interest (ADD before SSTORE)
                for j in i.saturating_sub(15)..i {
                    if self.bytecode[j] == 0x01 { // ADD (increase OI)
                        is_open_interest = true;
                    }
                }

                // Check for concentration cap (GT check before SSTORE)
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x11 { // GT (cap check)
                        has_cap = true;
                    }
                }

                if is_open_interest && !has_cap {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_predictable_settlement_time(&self) -> Option<usize> {
        // Look for: Fixed settlement time without randomization
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let mut has_fixed_time = false;
                let mut has_randomization = false;

                // Check for fixed expiry (EQ or GT with constant)
                for j in i+1..i+10.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 || self.bytecode[j] == 0x11 { // EQ/GT
                        // Check if comparing to constant (PUSH)
                        if self.bytecode.get(j+1).map(|&b| b >= 0x60 && b <= 0x7f).unwrap_or(false) {
                            has_fixed_time = true;
                        }
                    }
                }

                // Check for randomization (MOD or BLOCKHASH)
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 || self.bytecode[j] == 0x40 { // MOD/BLOCKHASH
                        has_randomization = true;
                    }
                }

                if has_fixed_time && !has_randomization {
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
    fn test_exact_strike_settlement() {
        // EQ check at settlement
        let bytecode = vec![
            0x42, // TIMESTAMP
            0x00, 0x00,
            0x14, // EQ (exact strike)
            0x57, // JUMPI (binary payout)
        ];
        
        let detector = BinaryOptionPricePinningDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect exact strike settlement");
    }

    #[test]
    fn test_safe_with_twap() {
        // Settlement with TWAP
        let bytecode = vec![
            0x54, // SLOAD (price 1)
            0x54, // SLOAD (price 2)
            0x54, // SLOAD (price 3)
            0x04, // DIV (average)
            0x42, // TIMESTAMP
            0x11, // GT (strike check)
        ];
        
        let detector = BinaryOptionPricePinningDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        // TWAP reduces pinning risk
        assert!(vulns.len() < 3, "Should recognize TWAP protection");
    }
}
