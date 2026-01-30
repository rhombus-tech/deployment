use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandReporterCollusionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct BandProtocolReporterCollusionDetector {
    bytecode: Vec<u8>,
}

impl BandProtocolReporterCollusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BandReporterCollusionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect Band Protocol reference data aggregation without validator diversity checks
        if let Some(location) = self.has_band_aggregation_without_diversity() {
            vulnerabilities.push(BandReporterCollusionVulnerability {
                vulnerability_type: "Band Protocol Reporter Collusion".to_string(),
                location,
                severity: "High".to_string(),
                description: "Band Protocol data aggregation detected without validator diversity checks. Multiple reporters could collude to manipulate the median/average price. Implement minimum validator count and outlier detection.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect single Band reference without cross-validation
        if let Some(location) = self.has_single_band_reference() {
            vulnerabilities.push(BandReporterCollusionVulnerability {
                vulnerability_type: "Band Protocol Single Reporter Risk".to_string(),
                location,
                severity: "High".to_string(),
                description: "Single Band Protocol reference data query without validation from multiple reporters. A compromised reporter could provide malicious data.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_band_aggregation_without_diversity(&self) -> Option<usize> {
        // Pattern: STATICCALL to Band oracle + data aggregation without diversity checks
        // Band typically uses address patterns starting with 0xDA7a (mainnet) or specific test addresses
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Look for aggregation (ADD, DIV for averaging) without validator count checks
                let mut has_aggregation = false;
                let mut has_validator_check = false;
                
                for j in (i+1)..(i+30).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x01 || self.bytecode[j] == 0x04 { // ADD or DIV
                        has_aggregation = true;
                    }
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT (validator count check)
                        has_validator_check = true;
                    }
                }
                
                if has_aggregation && !has_validator_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_single_band_reference(&self) -> Option<usize> {
        // Pattern: Single STATICCALL to Band without multiple reporter validation
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Check if there's immediate usage without additional oracle calls
                let mut has_second_oracle_call = false;
                
                for j in (i+1)..(i+40).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xfa { // Another STATICCALL
                        has_second_oracle_call = true;
                        break;
                    }
                }
                
                if !has_second_oracle_call {
                    // Check if data is used in state changes (SSTORE)
                    for j in (i+1)..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
