use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserOpGriefingVulnerability {
    ValidationGasGriefing { description: String, location: usize, confidence: f32 },
    UnboundedValidationLoop { description: String, location: usize, confidence: f32 },
    StorageAccessViolation { description: String, location: usize, confidence: f32 },
    PaymasterGasDrain { description: String, location: usize, confidence: f32 },
}

pub struct UserOpGriefingDetector {
    bytecode: Vec<u8>,
}

impl UserOpGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<UserOpGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_validation_gas_griefing());
        vulnerabilities.extend(self.detect_unbounded_validation());
        vulnerabilities.extend(self.detect_storage_access_violations());
        vulnerabilities
    }
    
    fn detect_validation_gas_griefing(&self) -> Vec<UserOpGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let validate_sigs = [&[0x3a, 0x87, 0x1c, 0xdd][..], &[0x8e, 0x4a, 0x23, 0xd6][..]];
        for sig in &validate_sigs {
            for i in 0..self.bytecode.len().saturating_sub(4) {
                if &self.bytecode[i..i + 4] == *sig {
                    let section = &self.bytecode[i..std::cmp::min(i + 150, self.bytecode.len())];
                    let has_external_call = section.contains(&0xF1) || section.contains(&0xFA);
                    let has_gas_limit = section.windows(10).any(|w| w.contains(&0x5A) && w.contains(&0x10));
                    if has_external_call && !has_gas_limit {
                        vulnerabilities.push(UserOpGriefingVulnerability::ValidationGasGriefing {
                            description: format!("validateUserOp at PC {} makes external calls without gas limits. Attacker can deploy contract that consumes all gas during validation, griefing bundlers. ERC-4337: validation must be gas-bounded.", i),
                            location: i,
                            confidence: 0.91,
                        });
                    }
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_unbounded_validation(&self) -> Vec<UserOpGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if i + 100 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 100];
                let has_loop = section.contains(&0x57);
                let loop_bound_check = section.windows(8).any(|w| {
                    w.contains(&0x10) && w.contains(&0xFD)
                });
                let in_validation = section.windows(4).any(|w| w == &[0x3a, 0x87, 0x1c, 0xdd]);
                if has_loop && !loop_bound_check && in_validation {
                    vulnerabilities.push(UserOpGriefingVulnerability::UnboundedValidationLoop {
                        description: format!("Unbounded loop in validation at PC {}. Can cause validation to exceed gas limits. ERC-4337 best practice: limit iterations to small constant (e.g., max 10).", i),
                        location: i,
                        confidence: 0.88,
                    });
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_storage_access_violations(&self) -> Vec<UserOpGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if i + 120 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 120];
                let in_validation = section.windows(4).any(|w| w == &[0x3a, 0x87, 0x1c, 0xdd]);
                let writes_storage = section.contains(&0x55);
                let reads_external_storage = section.contains(&0xFA) && section.contains(&0x54);
                if in_validation && (writes_storage || reads_external_storage) {
                    vulnerabilities.push(UserOpGriefingVulnerability::StorageAccessViolation {
                        description: format!("Validation at PC {} accesses external storage or writes state. ERC-4337 prohibits this: validation can only read sender/paymaster associated storage. Violators banned from bundlers.", i),
                        location: i,
                        confidence: 0.94,
                    });
                }
            }
        }
        vulnerabilities
    }
}
