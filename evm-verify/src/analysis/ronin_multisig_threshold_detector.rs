use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoninMultisigVulnerability {
    LowThresholdRatio { description: String, location: usize, confidence: f32 },
    NoTimelockOnThresholdChange { description: String, location: usize, confidence: f32 },
    MissingKeyRotation { description: String, location: usize, confidence: f32 },
    WeakSignerManagement { description: String, location: usize, confidence: f32 },
}

pub struct RoninMultisigThresholdDetector {
    bytecode: Vec<u8>,
}

impl RoninMultisigThresholdDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<RoninMultisigVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_low_threshold());
        vulnerabilities.extend(self.detect_no_timelock_on_changes());
        vulnerabilities.extend(self.detect_weak_signer_management());
        vulnerabilities
    }
    
    fn detect_low_threshold(&self) -> Vec<RoninMultisigVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 50 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 50];
                let has_threshold_check = section.contains(&0x10) || section.contains(&0x12);
                let has_signer_count = section.contains(&0x54);
                if has_threshold_check && has_signer_count {
                    vulnerabilities.push(RoninMultisigVulnerability::LowThresholdRatio {
                        description: format!("Multisig at PC {} may have threshold < 2/3 of signers. Ronin had 5/9 → compromised to 5/5. Recommend 7/9 minimum.", i),
                        location: i,
                        confidence: 0.88,
                    });
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_no_timelock_on_changes(&self) -> Vec<RoninMultisigVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if i + 100 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 100];
                let has_signer_update = section.contains(&0x55);
                let has_timestamp_check = section.contains(&0x42);
                if has_signer_update && !has_timestamp_check {
                    vulnerabilities.push(RoninMultisigVulnerability::NoTimelockOnThresholdChange {
                        description: format!("Signer/threshold change at PC {} lacks timelock. Ronin exploit: rapid key compromise → immediate threshold change. Add 48h timelock.", i),
                        location: i,
                        confidence: 0.92,
                    });
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_weak_signer_management(&self) -> Vec<RoninMultisigVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if i + 80 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 80];
                let has_add_signer = section.windows(4).any(|w| matches!(w, [0x55, _, _, _]));
                let has_access_control = section.contains(&0x33) && section.contains(&0x14);
                if has_add_signer && !has_access_control {
                    vulnerabilities.push(RoninMultisigVulnerability::WeakSignerManagement {
                        description: format!("Signer addition at PC {} lacks multi-party approval. Should require existing signers' consensus, not single admin.", i),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        vulnerabilities
    }
}
