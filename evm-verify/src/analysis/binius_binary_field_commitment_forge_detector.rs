use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct BiniusBinaryFieldCommitmentForgeDetector {
    bytecode: Vec<u8>,
}

impl BiniusBinaryFieldCommitmentForgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_binary_field_commitment_forge() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Binary field commitments can be forged through malformed polynomial construction breaking proof soundness.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_tower_field_extension_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Tower field extension operations can be bypassed to create invalid proofs.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_binary_field_commitment_forge(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x18 { // XOR (binary field operation)
                let mut has_field_validation = false;
                let mut has_commitment = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x16 { // AND (field element check)
                        has_field_validation = true;
                    }
                    if bytecode[j] == 0x20 && !has_field_validation { // SHA3 (commit without validation)
                        has_commitment = true;
                    }
                }

                if has_commitment && !has_field_validation {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_tower_field_extension_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x02 { // MUL (field multiplication)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x18 { // XOR (tower extension)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0xFA { // STATICCALL (verify)
                                let mut has_degree_check = false;
                                for l in j..k {
                                    if bytecode[l] == 0x06 { // MOD (degree validation)
                                        has_degree_check = true;
                                        break;
                                    }
                                }
                                if !has_degree_check {
                                    return Some(i);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }
}
