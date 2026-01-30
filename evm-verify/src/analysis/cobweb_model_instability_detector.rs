#[derive(Debug, Clone, PartialEq)]
pub enum CobwebModelVulnerability {
    OscillatingPrices { pc: usize, oscillation_severity: f64, description: String },
}

pub struct CobwebModelInstabilityDetector { 
    bytecode: Vec<u8> 
}

impl CobwebModelInstabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { 
        Self { bytecode } 
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<CobwebModelVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect delayed price adjustments causing oscillations
        if let Some((pc, severity)) = self.detect_delayed_supply_demand_adjustment() {
            vulnerabilities.push(CobwebModelVulnerability::OscillatingPrices {
                pc,
                oscillation_severity: severity,
                description: format!(
                    "Price adjustment mechanism has delays causing cobweb oscillations (severity: {:.2})",
                    severity
                ),
            });
        }
        
        // Detect overshooting price corrections
        if let Some((pc, severity)) = self.detect_overshooting_corrections() {
            vulnerabilities.push(CobwebModelVulnerability::OscillatingPrices {
                pc,
                oscillation_severity: severity,
                description: format!(
                    "Price corrections overshoot equilibrium creating unstable oscillations (severity: {:.2})",
                    severity
                ),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_delayed_supply_demand_adjustment(&self) -> Option<(usize, f64)> {
        // Look for price updates based on past state rather than current
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Pattern: load old price -> update -> store
            if self.bytecode[i] == 0x54 { // SLOAD (loading price)
                let mut has_time_lag = false;
                let mut has_update = false;
                
                // Check for timestamp-based lag
                for j in i..i.saturating_add(20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        // Check for SUB (calculating time difference)
                        for k in j..j.saturating_add(8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 { // SUB
                                has_time_lag = true;
                            }
                        }
                    }
                    
                    // Check for price adjustment
                    if matches!(self.bytecode[j], 0x02 | 0x04) { // MUL or DIV
                        has_update = true;
                    }
                }
                
                // Delayed adjustment = cobweb potential
                if has_time_lag && has_update {
                    return Some((i, 0.6)); // 60% severity
                }
            }
        }
        None
    }
    
    fn detect_overshooting_corrections(&self) -> Option<(usize, f64)> {
        // Look for price corrections without dampening
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Pattern: price difference * large multiplier
            if self.bytecode[i] == 0x03 { // SUB (price difference)
                let mut has_large_multiplier = false;
                let mut no_dampening = true;
                
                for j in i..i.saturating_add(20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL
                        // Check if multiplier is large (look for large PUSH)
                        for k in j.saturating_sub(5)..j {
                            if self.bytecode[k] >= 0x62 { // PUSH3 or larger (large multiplier)
                                has_large_multiplier = true;
                            }
                        }
                        
                        // Check for dampening (DIV after MUL)
                        for k in j..j.saturating_add(8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x04 { // DIV (dampening factor)
                                no_dampening = false;
                            }
                        }
                    }
                }
                
                // Large undampened corrections = oscillation risk
                if has_large_multiplier && no_dampening {
                    return Some((i, 0.75)); // 75% severity
                }
            }
        }
        None
    }
}
