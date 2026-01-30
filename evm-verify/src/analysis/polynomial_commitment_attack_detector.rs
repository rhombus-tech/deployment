/// Polynomial Commitment Attack Detector (KZG/IPA)
use crate::bytecode::SecurityFinding;

pub struct PolynomialCommitmentAttackDetector {
    bytecode: Vec<u8>,
}

impl PolynomialCommitmentAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Polynomial commitment attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.84,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(65) {
            if self.check_commitment_attack(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_commitment_attack(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for polynomial commitment verification without proper validation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // verifyKZG, verifyIPA, checkCommitment selectors
            if matches!(self.bytecode[pos+1], 0x2d | 0x5e | 0x89 | 0xb4) {
                let mut has_degree_check = false;
                let mut has_point_validation = false;
                let mut has_pairing_verification = false;
                let mut validates_commitment_format = false;
                
                if pos + 60 < self.bytecode.len() {
                    // Check for polynomial degree validation
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            // Should check degree doesn't exceed maximum
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                has_degree_check = true;
                            }
                        }
                    }
                    
                    // Check for evaluation point validation
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x09 { // MOD (checking point in field)
                            has_point_validation = true;
                        }
                    }
                    
                    // Check for pairing check (KZG) or IPA verification
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL (to bn256 precompiles)
                            has_pairing_verification = true;
                        }
                    }
                    
                    // Check for commitment format validation (G1/G2 point checks)
                    let mut format_checks = 0;
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x14 { // EQ (checking format)
                            format_checks += 1;
                        }
                    }
                    if format_checks >= 2 {
                        validates_commitment_format = true;
                    }
                }
                
                // Vulnerable if:
                // 1. Doesn't validate polynomial degree
                // 2. Doesn't check evaluation point is valid
                // 3. Missing or incorrect pairing check
                // 4. Doesn't validate commitment format
                return !has_degree_check || !has_point_validation || !has_pairing_verification || !validates_commitment_format;
            }
        }
        false
    }
}
