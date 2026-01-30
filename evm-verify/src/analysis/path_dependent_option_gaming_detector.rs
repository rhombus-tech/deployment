use serde::{Deserialize, Serialize};

/// Path-Dependent Option Gaming Detector
/// 
/// Path-dependent options: Payoff depends on the price path, not just final price
/// Examples: Asian (average price), Lookback (min/max), Barrier (knock-in/out)
///
/// Key Attacks:
/// 1. Manipulate price path to trigger barriers
/// 2. Strategic timing to affect average price
/// 3. Exploit sampling frequency
/// 4. Min/max manipulation in lookback options
///
/// Real-World Context:
/// - Dopex (barrier options)
/// - Lyra (path-dependent exotic options)
/// - Potential $30M+ in path-dependent options TVL

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathDependentOptionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PathDependentOptionGamingDetector {
    bytecode: Vec<u8>,
}

impl PathDependentOptionGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PathDependentOptionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Barrier Option Without Time Delay
        if let Some(loc) = self.has_barrier_without_time_delay() {
            vulnerabilities.push(PathDependentOptionVulnerability {
                vulnerability_type: "Barrier Trigger Without Time Delay".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Barrier option can be triggered instantly without time delay, enabling flash manipulation".to_string(),
                confidence: 0.85,
            });
        }

        // Pattern 2: Asian Option Insufficient Sampling
        if let Some(loc) = self.has_asian_option_insufficient_sampling() {
            vulnerabilities.push(PathDependentOptionVulnerability {
                vulnerability_type: "Asian Option Insufficient Sampling".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Average price calculation uses too few samples, vulnerable to manipulation".to_string(),
                confidence: 0.80,
            });
        }

        // Pattern 3: Lookback Option Min/Max Manipulation
        if let Some(loc) = self.has_lookback_manipulation_risk() {
            vulnerabilities.push(PathDependentOptionVulnerability {
                vulnerability_type: "Lookback Min/Max Manipulation".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Min/max price tracking vulnerable to single-block manipulation".to_string(),
                confidence: 0.75,
            });
        }

        // Pattern 4: Path Tracking Without Bounds
        if let Some(loc) = self.has_path_tracking_without_bounds() {
            vulnerabilities.push(PathDependentOptionVulnerability {
                vulnerability_type: "Path Tracking Without Bounds".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Price path tracking lacks sanity bounds or outlier filters".to_string(),
                confidence: 0.70,
            });
        }

        // Pattern 5: Barrier Reset Gaming
        if let Some(loc) = self.has_barrier_reset_gaming_risk() {
            vulnerabilities.push(PathDependentOptionVulnerability {
                vulnerability_type: "Barrier Reset Gaming".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Barrier levels can be reset or manipulated after option creation".to_string(),
                confidence: 0.75,
            });
        }

        vulnerabilities
    }

    fn has_barrier_without_time_delay(&self) -> Option<usize> {
        // Look for: Barrier check (GT/LT) without time lock
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Barrier check pattern
            if self.bytecode[i] == 0x11 || self.bytecode[i] == 0x10 { // GT/LT (barrier)
                let mut has_barrier_trigger = false;
                let mut has_time_delay = false;

                // Check for state change (barrier knocked)
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE (barrier state)
                        has_barrier_trigger = true;
                    }
                }

                // Check for time delay (TIMESTAMP + ADD/SUB + GT)
                for j in i.saturating_sub(20)..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        // Look for time arithmetic
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if (self.bytecode[k] == 0x01 || self.bytecode[k] == 0x03) && // ADD/SUB
                               self.bytecode.get(k+2) == Some(&0x11) { // GT (delay check)
                                has_time_delay = true;
                            }
                        }
                    }
                }

                if has_barrier_trigger && !has_time_delay {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_asian_option_insufficient_sampling(&self) -> Option<usize> {
        // Look for: Average price calculation with few samples
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Pattern: Multiple SLOAD + ADD (accumulate) + DIV (average)
            if self.bytecode[i] == 0x01 { // ADD (accumulate prices)
                let mut has_averaging = false;
                let mut sample_count = 0;

                // Count price reads
                for j in i.saturating_sub(25)..i {
                    if self.bytecode[j] == 0x54 { // SLOAD (price sample)
                        sample_count += 1;
                    }
                }

                // Check for averaging
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV (calculate average)
                        has_averaging = true;
                    }
                }

                // Asian options need many samples (at least 5-10)
                if has_averaging && sample_count > 0 && sample_count < 5 {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_lookback_manipulation_risk(&self) -> Option<usize> {
        // Look for: Min/Max tracking without multi-block requirement
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Pattern: GT/LT (compare for min/max) + SSTORE (update)
            if self.bytecode[i] == 0x11 || self.bytecode[i] == 0x10 { // GT/LT
                let mut is_minmax_update = false;
                let mut has_block_delay = false;

                // Check for SSTORE (updating min/max)
                for j in i+1..i+10.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE
                        is_minmax_update = true;
                    }
                }

                // Check for block number check (prevents single-block manipulation)
                for j in i.saturating_sub(15)..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x43 { // NUMBER (block number)
                        has_block_delay = true;
                    }
                }

                if is_minmax_update && !has_block_delay {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_path_tracking_without_bounds(&self) -> Option<usize> {
        // Look for: Path recording without sanity checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Pattern: SSTORE (record price) without bounds check
            if self.bytecode[i] == 0x55 { // SSTORE (save price to path)
                let mut is_price_recording = false;
                let mut has_bounds_check = false;

                // Check if recording price (SLOAD before SSTORE)
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x54 { // SLOAD (read price)
                        is_price_recording = true;
                    }
                }

                // Check for bounds/sanity check (GT/LT before SSTORE)
                for j in i.saturating_sub(15)..i {
                    if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10 { // GT/LT
                        has_bounds_check = true;
                    }
                }

                if is_price_recording && !has_bounds_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_barrier_reset_gaming_risk(&self) -> Option<usize> {
        // Look for: Barrier level SSTORE without proper authorization
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE
                let mut is_barrier_update = false;
                let mut has_auth_check = false;

                // Check if this is barrier level update (specific storage slot)
                // In practice, we look for updates after comparisons
                for j in i.saturating_sub(20)..i {
                    if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10 {
                        is_barrier_update = true;
                    }
                }

                // Check for authorization (CALLER + EQ check)
                for j in i.saturating_sub(25)..i {
                    if self.bytecode[j] == 0x33 { // CALLER
                        for k in j+1..i {
                            if self.bytecode[k] == 0x14 { // EQ (auth check)
                                has_auth_check = true;
                            }
                        }
                    }
                }

                if is_barrier_update && !has_auth_check {
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
    fn test_barrier_without_delay() {
        // Barrier check without time delay
        let bytecode = vec![
            0x11, // GT (barrier check)
            0x57, // JUMPI
            0x55, // SSTORE (barrier triggered)
        ];
        
        let detector = PathDependentOptionGamingDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect barrier without time delay");
    }

    #[test]
    fn test_asian_option_few_samples() {
        // Average with only 2 samples
        let bytecode = vec![
            0x54, // SLOAD (price 1)
            0x54, // SLOAD (price 2)
            0x01, // ADD
            0x04, // DIV (average)
        ];
        
        let detector = PathDependentOptionGamingDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect insufficient sampling");
    }

    #[test]
    fn test_safe_asian_many_samples() {
        // Average with 6 samples
        let bytecode = vec![
            0x54, 0x54, 0x54, 0x54, 0x54, 0x54, // 6 SLOADs
            0x01, 0x01, 0x01, 0x01, 0x01, // ADDs
            0x04, // DIV (average)
        ];
        
        let detector = PathDependentOptionGamingDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        // Sufficient samples reduce risk
        let asian_vulns: Vec<_> = vulns.iter().filter(|v| v.vulnerability_type.contains("Asian")).collect();
        assert_eq!(asian_vulns.len(), 0, "Should not flag sufficient sampling");
    }
}
