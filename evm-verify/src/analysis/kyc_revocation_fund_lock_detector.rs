use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KycRevocationFundLockVulnerability {
    IrrevocableFundLock { description: String, location: usize, confidence: f32 },
    NoGracePeriod { description: String, location: usize, confidence: f32 },
    MissingRecoveryMechanism { description: String, location: usize, confidence: f32 },
}

pub struct KycRevocationFundLockDetector {
    bytecode: Vec<u8>,
}

impl KycRevocationFundLockDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<KycRevocationFundLockVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.enforces_kyc() && !self.allows_withdrawal_before_lock() {
            vulnerabilities.push(KycRevocationFundLockVulnerability::IrrevocableFundLock {
                description: "KYC enforcement without withdrawal window - immediate fund lock".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.revokes_access() && !self.has_grace_period() {
            vulnerabilities.push(KycRevocationFundLockVulnerability::NoGracePeriod {
                description: "Access revocation without grace period - abrupt fund lockout".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.locks_on_compliance() && !self.has_recovery_path() {
            vulnerabilities.push(KycRevocationFundLockVulnerability::MissingRecoveryMechanism {
                description: "Compliance lock without recovery mechanism - permanent fund loss risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn enforces_kyc(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 3 && iszero_count > 2 && jumpi_count > 3
    }
    
    fn allows_withdrawal_before_lock(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        timestamp_count > 1 && lt_count > 1
    }
    
    fn revokes_access(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sstore_count > 2 && iszero_count > 1
    }
    
    fn has_grace_period(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        timestamp_count > 1 && add_count > 1 && gt_count > 0
    }
    
    fn locks_on_compliance(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        sload_count > 2 && eq_count > 1 && revert_count > 0
    }
    
    fn has_recovery_path(&self) -> bool {
        // Admin override or multi-sig recovery
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let or_count = self.bytecode.iter().filter(|&&b| b == 0x17).count();
        caller_count > 1 && eq_count > 2 && or_count > 0
    }
}
