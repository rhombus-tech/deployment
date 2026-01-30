/// Shielded Pool Linkability Detector
use crate::bytecode::SecurityFinding;

pub struct ShieldedPoolLinkabilityDetector {
    bytecode: Vec<u8>,
}

impl ShieldedPoolLinkabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Shielded pool transaction linkability at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(75) {
            if self.check_linkability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_linkability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for shielded pool operations with linkability issues
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // deposit, withdraw, transfer selectors for shielded pools
            if matches!(self.bytecode[pos+1], 0xb6 | 0x2e | 0x3c | 0xd2) {
                let mut uses_nullifier = false;
                let mut has_commitment_scheme = false;
                let mut prevents_amount_correlation = false;
                let mut uses_randomness = false;
                
                if pos + 70 < self.bytecode.len() {
                    // Check for nullifier usage (prevents double-spend)
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x20 { // SHA3/KECCAK256 (nullifier hash)
                            uses_nullifier = true;
                        }
                    }
                    
                    // Check for commitment scheme (Pedersen, Poseidon)
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL to crypto precompile
                            has_commitment_scheme = true;
                        }
                    }
                    
                    // Check for amount obfuscation
                    let mut mul_operations = 0;
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 { // MUL (mixing amounts)
                            mul_operations += 1;
                        }
                    }
                    if mul_operations >= 2 {
                        prevents_amount_correlation = true;
                    }
                    
                    // Check for randomness in commitments
                    for j in (pos + 5)..(pos + 70).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x40 || self.bytecode[j] == 0x44 { // BLOCKHASH, DIFFICULTY
                            uses_randomness = true;
                        }
                    }
                }
                
                // Vulnerable if transactions can be linked via:
                // 1. Missing nullifier system
                // 2. Weak commitment scheme
                // 3. Amount correlation possible
                // 4. Deterministic commitments (no randomness)
                return !uses_nullifier || !has_commitment_scheme || !prevents_amount_correlation || !uses_randomness;
            }
        }
        false
    }
}
