use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DistributedValidatorKeyManagementVulnerability {
    InsecureKeySharing { description: String, location: usize, confidence: f32 },
    MissingKeyRotation { description: String, location: usize, confidence: f32 },
    ThresholdBypass { description: String, location: usize, confidence: f32 },
}

pub struct DistributedValidatorKeyManagementDetector {
    bytecode: Vec<u8>,
}

impl DistributedValidatorKeyManagementDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DistributedValidatorKeyManagementVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.manages_validator_keys() && !self.encrypts_key_shares() {
            vulnerabilities.push(DistributedValidatorKeyManagementVulnerability::InsecureKeySharing {
                description: "Validator key management without encryption - insecure key sharing".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.stores_key_material() && !self.supports_key_rotation() {
            vulnerabilities.push(DistributedValidatorKeyManagementVulnerability::MissingKeyRotation {
                description: "Key storage without rotation mechanism - compromised key persistence".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.uses_threshold_signing() && !self.validates_threshold() {
            vulnerabilities.push(DistributedValidatorKeyManagementVulnerability::ThresholdBypass {
                description: "Threshold signing without validation - signature threshold bypass risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn manages_validator_keys(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xF4).count();
        sload_count > 5 && sstore_count > 3 && call_count > 2
    }
    
    fn encrypts_key_shares(&self) -> bool {
        // Look for cryptographic operations (hashing, xor)
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let xor_count = self.bytecode.iter().filter(|&&b| b == 0x18).count();
        sha3_count > 2 || xor_count > 3
    }
    
    fn stores_key_material(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sstore_count > 5
    }
    
    fn supports_key_rotation(&self) -> bool {
        // Check for update mechanism with old key removal
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        sstore_count > 4 && sload_count > 6 && timestamp_count > 1
    }
    
    fn uses_threshold_signing(&self) -> bool {
        // Multiple signature checks
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        staticcall_count > 3 && eq_count > 5
    }
    
    fn validates_threshold(&self) -> bool {
        // Counter checks and comparisons
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 3 && (lt_count + gt_count) > 2
    }
}
