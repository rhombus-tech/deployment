/// Data Withholding Attack Detector
use crate::bytecode::SecurityFinding;

pub struct DataWithholdingAttackDetector {
    bytecode: Vec<u8>,
}

impl DataWithholdingAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Data withholding attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(75) {
            if self.check_data_withholding(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_data_withholding(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for data availability mechanisms that can be bypassed
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // publishData, commitBatch, submitBlock selectors
            if matches!(self.bytecode[pos+1], 0x19 | 0x3d | 0x62 | 0x9f) {
                let mut requires_data_availability_proof = false;
                let mut has_data_root_verification = false;
                let mut enforces_availability_sampling = false;
                let mut prevents_selective_disclosure = false;
                
                if pos + 70 < self.bytecode.len() {
                    // Check for DA proof requirement
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL to DA layer
                            requires_data_availability_proof = true;
                        }
                    }
                    
                    // Check for data root verification (Merkle proof)
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x20 { // SHA3/KECCAK256 (Merkle root)
                            has_data_root_verification = true;
                        }
                    }
                    
                    // Check for data availability sampling enforcement
                    let mut sample_checks = 0;
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x14 { // EQ (checking samples)
                            sample_checks += 1;
                        }
                    }
                    if sample_checks >= 3 {
                        enforces_availability_sampling = true;
                    }
                    
                    // Check for preventing selective disclosure
                    for j in (pos + 5)..(pos + 70).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 && j + 3 < self.bytecode.len() { // SSTORE
                            // Should store commitment to all data
                            if self.bytecode[j + 2] == 0x20 { // SHA3 hash stored
                                prevents_selective_disclosure = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if data withholding is possible via:
                // 1. No DA proof required
                // 2. No data root verification
                // 3. No availability sampling
                // 4. Selective disclosure possible
                return !requires_data_availability_proof || !has_data_root_verification || !enforces_availability_sampling || !prevents_selective_disclosure;
            }
        }
        false
    }
}
