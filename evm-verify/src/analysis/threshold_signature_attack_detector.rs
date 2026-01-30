use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThresholdSignatureAttackDetectorVulnerability {
    TSSKeyRecovery { description: String, location: usize },
}
pub struct ThresholdSignatureAttackDetector { bytecode: Vec<u8> }
impl ThresholdSignatureAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ThresholdSignatureAttackDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        let ecrecover_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        if ecrecover_count >= 2 {
            let has_threshold_check = self.bytecode.windows(15)
                .any(|w| w.iter().filter(|&&b| b == 0x14).count() >= 2);
            if !has_threshold_check {
                vulnerabilities.push(ThresholdSignatureAttackDetectorVulnerability::TSSKeyRecovery {
                    description: "TSS without proper threshold validation".to_string(), location: 0,
                });
            }
        }
        vulnerabilities
    }
}