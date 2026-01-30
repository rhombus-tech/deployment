use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FluxProtocolAveragingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct FluxProtocolAveragingDetector {
    bytecode: Vec<u8>,
}

impl FluxProtocolAveragingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FluxProtocolAveragingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect Flux price averaging without outlier detection
        if let Some(location) = self.has_averaging_without_outlier_detection() {
            vulnerabilities.push(FluxProtocolAveragingVulnerability {
                vulnerability_type: "Flux Protocol Averaging Attack".to_string(),
                location,
                severity: "High".to_string(),
                description: "Flux Protocol price averaging without outlier detection. Malicious data providers can skew the average by submitting extreme values. Implement median or trimmed mean calculations.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect simple mean without weighted averaging
        if let Some(location) = self.has_simple_mean_without_weighting() {
            vulnerabilities.push(FluxProtocolAveragingVulnerability {
                vulnerability_type: "Flux Non-Weighted Averaging".to_string(),
                location,
                severity: "Medium".to_string(),
                description: "Simple arithmetic mean used without stake-weighted averaging. Low-stake providers have equal weight as high-stake providers. Use stake-weighted or reputation-weighted aggregation.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect insufficient data provider count for averaging
        if let Some(location) = self.has_insufficient_provider_count() {
            vulnerabilities.push(FluxProtocolAveragingVulnerability {
                vulnerability_type: "Insufficient Flux Data Providers".to_string(),
                location,
                severity: "High".to_string(),
                description: "Price averaging with insufficient data provider count. Small provider sets are easier to manipulate. Enforce minimum provider threshold (recommended: 5+).".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_averaging_without_outlier_detection(&self) -> Option<usize> {
        // Pattern: ADD/DIV averaging without outlier removal (no sorting or bounds checking)
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 { // ADD (summing values)
                // Look for DIV (calculating average)
                let mut has_division = false;
                let mut has_outlier_check = false;
                
                for j in i+1..i+40.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV
                        has_division = true;
                    }
                    // Check for outlier detection (multiple LT/GT comparisons indicating bounds)
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 {
                                has_outlier_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if has_division && !has_outlier_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_simple_mean_without_weighting(&self) -> Option<usize> {
        // Pattern: Simple ADD/DIV without MUL (stake weighting)
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x01 { // ADD
                let mut has_division = false;
                let mut has_weighting = false;
                
                // Look for DIV after ADD
                for j in i+1..i+30.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV
                        has_division = true;
                    }
                    // Check for MUL (weighted multiplication)
                    if self.bytecode[j] == 0x02 { // MUL
                        has_weighting = true;
                    }
                }
                
                // Simple mean: ADD followed by DIV without MUL
                if has_division && !has_weighting {
                    // Verify this is in aggregation context (multiple values)
                    let mut loop_count = 0;
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x56 || self.bytecode[j] == 0x57 { // JUMP or JUMPI
                            loop_count += 1;
                        }
                    }
                    if loop_count > 0 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_insufficient_provider_count(&self) -> Option<usize> {
        // Pattern: Aggregation with low minimum provider check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for count check (LT comparison with small number)
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT
                // Check if comparing against small value (1-4 providers)
                for j in i.saturating_sub(5)..i {
                    if self.bytecode[j] == 0x60 { // PUSH1
                        if j + 1 < self.bytecode.len() {
                            let threshold = self.bytecode[j + 1];
                            // If threshold is less than 5
                            if threshold < 5 {
                                // Check if followed by aggregation logic
                                for k in i+1..i+20.min(self.bytecode.len()) {
                                    if self.bytecode[k] == 0x01 { // ADD (aggregation)
                                        return Some(j);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
}
