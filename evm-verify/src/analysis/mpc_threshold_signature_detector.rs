use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcThresholdVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MpcThresholdSignatureDetector {
    bytecode: Vec<u8>,
}

impl MpcThresholdSignatureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MpcThresholdVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unvalidated_signature_shares());
        vulnerabilities.extend(self.detect_missing_participant_verification());
        vulnerabilities.extend(self.detect_signature_share_reuse());

        vulnerabilities
    }

    fn detect_unvalidated_signature_shares(&self) -> Vec<MpcThresholdVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for signature aggregation (ADD or MUL on multiple values)
            if opcode == 0x01 || opcode == 0x02 { // ADD or MUL
                let start = if pc > 80 { pc - 80 } else { 0 };
                
                // Count CALLDATALOAD operations (loading signature shares)
                let share_loads = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count();
                
                // Check for validation (modexp precompile for proof of possession)
                let has_validation = self.bytecode[start..pc].windows(2).any(|w| {
                    w[0] == 0x60 && w[1] == 0x05 // PUSH1 5 (modexp precompile)
                });
                
                if share_loads >= 2 && !has_validation {
                    vulns.push(MpcThresholdVulnerability {
                        pc,
                        vulnerability_type: "UnvalidatedSignatureShares".to_string(),
                        description: format!(
                            "Signature shares aggregated at PC {} without validation. Rogue key attack: \
                            malicious participant submits share sigma_malicious = sigma_honest * r, causing \
                            final signature to be under attacker's key. Requires proof of possession (PoP) \
                            for each share: verify participant knows discrete log of their public key share.",
                            pc
                        ),
                        confidence: 0.80,
                    });
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_missing_participant_verification(&self) -> Vec<MpcThresholdVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE storing aggregated signature
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                
                // Check for arithmetic operations (combining shares)
                let has_combining = self.bytecode[start..pc].iter().any(|&b| b == 0x01 || b == 0x02);
                
                // Check for participant list validation (SLOAD checking allowed signers)
                let sload_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count();
                let has_eq = self.bytecode[start..pc].iter().any(|&b| b == 0x14);
                
                if has_combining && sload_count < 2 && !has_eq {
                    vulns.push(MpcThresholdVulnerability {
                        pc,
                        vulnerability_type: "MissingParticipantVerification".to_string(),
                        description: format!(
                            "Signature aggregation at PC {} without participant verification. Anyone can \
                            contribute shares. Attacker can: (1) Add unauthorized signatures, (2) Replace \
                            legitimate shares, (3) Bypass threshold requirements. Verify each participant \
                            is in authorized signer set before accepting their share.",
                            pc
                        ),
                        confidence: 0.75,
                    });
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_signature_share_reuse(&self) -> Vec<MpcThresholdVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Signature combination operation
            if opcode == 0x01 || opcode == 0x02 {
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window_end = (pc + 60).min(self.bytecode.len());
                
                // Check if shares are from calldata (user input)
                let has_calldata = self.bytecode[start..pc].iter().any(|&b| b == 0x35);
                
                // Check for uniqueness validation (hash share, check if already used)
                let has_hash = self.bytecode[start..window_end].iter().any(|&b| b == 0x20);
                let has_sload_check = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_calldata && !(has_hash && has_sload_check) {
                    vulns.push(MpcThresholdVulnerability {
                        pc,
                        vulnerability_type: "SignatureShareReuse".to_string(),
                        description: format!(
                            "Signature shares at PC {} without replay protection. Same share can be submitted \
                            multiple times across different signing rounds. Attacker can: (1) Reuse old shares \
                            in new signatures, (2) Forge signatures with replayed components. Store hash of \
                            (share, nonce, message) to prevent reuse.",
                            pc
                        ),
                        confidence: 0.70,
                    });
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
