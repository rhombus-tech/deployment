/// Fiat-Shamir Transform Weakness Detector
use crate::bytecode::SecurityFinding;

pub struct FiatShamirWeaknessDetector {
    bytecode: Vec<u8>,
}

impl FiatShamirWeaknessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Fiat-Shamir transform weakness at PC {}", location),
                pc: location,
                confidence: 0.82,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_fiat_shamir_weakness(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_fiat_shamir_weakness(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for Fiat-Shamir challenge generation without proper transcript
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // generateChallenge, hashTranscript, computeFiatShamir selectors
            if matches!(self.bytecode[pos+1], 0x3a | 0x6d | 0x91 | 0xc8) {
                let mut has_complete_transcript = false;
                let mut uses_secure_hash = false;
                let mut includes_public_inputs = false;
                let mut prevents_transcript_manipulation = false;
                
                if pos + 55 < self.bytecode.len() {
                    // Check for complete transcript hashing (multiple items hashed together)
                    let mut hash_operations = 0;
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x20 { // SHA3/KECCAK256
                            hash_operations += 1;
                        }
                    }
                    if hash_operations >= 1 {
                        uses_secure_hash = true;
                    }
                    
                    // Check if includes all commitments in transcript
                    let mut mload_operations = 0;
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x51 { // MLOAD (reading transcript items)
                            mload_operations += 1;
                        }
                    }
                    if mload_operations >= 3 {
                        has_complete_transcript = true;
                    }
                    
                    // Check if public inputs are included in hash
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD (reading public inputs)
                            includes_public_inputs = true;
                        }
                    }
                    
                    // Check for domain separation or nonce to prevent replay
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x60 && j + 1 < self.bytecode.len() {
                            // PUSH1 with a constant (domain separator)
                            prevents_transcript_manipulation = true;
                        }
                    }
                }
                
                // Vulnerable if:
                // 1. Incomplete transcript (missing commitments)
                // 2. Weak hash function or no hashing
                // 3. Public inputs not included
                // 4. No domain separation
                return !has_complete_transcript || !uses_secure_hash || !includes_public_inputs || !prevents_transcript_manipulation;
            }
        }
        false
    }
}
