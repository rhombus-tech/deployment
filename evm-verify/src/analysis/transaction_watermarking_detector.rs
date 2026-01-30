#[derive(Debug, Clone, PartialEq)]
pub enum WatermarkingVulnerability {
    Deanonymization { pc: usize, linkability_risk: f64, description: String },
}

pub struct TransactionWatermarkingDetector { 
    bytecode: Vec<u8> 
}

impl TransactionWatermarkingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { 
        Self { bytecode } 
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<WatermarkingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect fingerprinting via gas patterns
        if let Some((pc, risk)) = self.detect_gas_pattern_fingerprinting() {
            vulnerabilities.push(WatermarkingVulnerability::Deanonymization {
                pc,
                linkability_risk: risk,
                description: format!(
                    "Contract creates unique gas patterns per user enabling transaction linkability (risk: {:.0}%)",
                    risk * 100.0
                ),
            });
        }
        
        // Detect nonce-based tracking
        if let Some((pc, risk)) = self.detect_nonce_tracking_watermark() {
            vulnerabilities.push(WatermarkingVulnerability::Deanonymization {
                pc,
                linkability_risk: risk,
                description: format!(
                    "Contract embeds user-specific nonces in transactions enabling deanonymization (risk: {:.0}%)",
                    risk * 100.0
                ),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_gas_pattern_fingerprinting(&self) -> Option<(usize, f64)> {
        // Look for user-specific gas consumption patterns
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Pattern: CALLER followed by MOD or AND (user-specific branching)
            if self.bytecode[i] == 0x33 { // CALLER
                for j in i..i.saturating_add(10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 || self.bytecode[j] == 0x16 { // MOD or AND
                        // Check if result affects execution path
                        for k in j..j.saturating_add(10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x57 { // JUMPI (conditional)
                                // User-specific branching creates fingerprint
                                return Some((i, 0.7)); // 70% linkability risk
                            }
                        }
                    }
                }
            }
        }
        None
    }
    
    fn detect_nonce_tracking_watermark(&self) -> Option<(usize, f64)> {
        // Look for sequential nonce embedding in logs
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if (0xa0..=0xa4).contains(&self.bytecode[i]) { // LOGx
                let mut has_caller = false;
                let mut has_counter = false;
                
                // Check if log includes caller address
                for j in (i.saturating_sub(15)..i).rev() {
                    if self.bytecode[j] == 0x33 { // CALLER
                        has_caller = true;
                    }
                    // Check for counter (SLOAD + ADD pattern)
                    if self.bytecode[j] == 0x54 { // SLOAD
                        for k in j..j.saturating_add(5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 { // ADD (increment)
                                has_counter = true;
                            }
                        }
                    }
                }
                
                // Caller + sequential counter = watermark
                if has_caller && has_counter {
                    return Some((i, 0.85)); // 85% linkability risk
                }
            }
        }
        None
    }
}
