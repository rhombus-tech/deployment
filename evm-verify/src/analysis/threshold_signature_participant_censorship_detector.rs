use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdCensorshipVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ThresholdSignatureParticipantCensorshipDetector {
    bytecode: Vec<u8>,
}

impl ThresholdSignatureParticipantCensorshipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ThresholdCensorshipVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect threshold count check without individual signer tracking
        vulnerabilities.extend(self.detect_untracked_signers());
        
        // Detect signature verification without uniqueness check
        vulnerabilities.extend(self.detect_signature_reuse());
        
        // Detect ecrecover without signer address validation
        vulnerabilities.extend(self.detect_unvalidated_signers());

        vulnerabilities
    }

    fn detect_untracked_signers(&self) -> Vec<ThresholdCensorshipVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut has_threshold_check = false;
        let mut has_signer_storage = false;

        // First pass: find threshold comparison
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // LT/GT comparison (threshold check: sigCount >= threshold)
            if opcode == 0x10 || opcode == 0x11 {
                let window_start = if pc > 30 { pc - 30 } else { 0 };
                let window_end = (pc + 30).min(self.bytecode.len());
                
                // Check if loading signature count from storage
                if self.bytecode[window_start..window_end].iter().any(|&b| b == 0x54) {
                    has_threshold_check = true;
                    break;
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        if !has_threshold_check {
            return vulns;
        }

        // Second pass: check for signer address storage (mapping or array)
        pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for pattern: address from ecrecover, then SSTORE
            if self.bytecode[pc] == 0x01 { // Potential ecrecover result on stack
                let window_end = (pc + 50).min(self.bytecode.len());
                // Check if address is stored (tracking who signed)
                if self.bytecode[(pc + 1)..window_end].iter().any(|&b| b == 0x55) {
                    has_signer_storage = true;
                    break;
                }
            }
            
            pc += 1;
        }

        if has_threshold_check && !has_signer_storage {
            vulns.push(ThresholdCensorshipVulnerability {
                pc: 0,
                vulnerability_type: "UntrackedSigners".to_string(),
                description: "Threshold signature counts signatures without tracking signer identities. \
                    Enables censorship: coordinator can selectively exclude specific signers by \
                    substituting their signatures with duplicates from compliant signers. \
                    Without per-signer tracking, same signer can sign multiple times to reach threshold. \
                    Store and verify each signer address uniquely.".to_string(),
                confidence: 0.80,
            });
        }

        vulns
    }

    fn detect_signature_reuse(&self) -> Vec<ThresholdCensorshipVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for ecrecover precompile call
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                let window_end = (pc + 60).min(self.bytecode.len());
                let mut has_staticcall = false;
                let mut has_duplicate_check = false;
                
                // Find the STATICCALL to ecrecover
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA {
                        has_staticcall = true;
                        
                        // Check if result is compared against existing signers (duplicate check)
                        let result_end = (check_pc + 40).min(self.bytecode.len());
                        // Look for SLOAD then EQ (checking if address already signed)
                        let has_sload = self.bytecode[(check_pc + 1)..result_end].iter().any(|&b| b == 0x54);
                        let has_eq = self.bytecode[(check_pc + 1)..result_end].iter().any(|&b| b == 0x14);
                        has_duplicate_check = has_sload && has_eq;
                        break;
                    }
                }
                
                if has_staticcall && !has_duplicate_check {
                    vulns.push(ThresholdCensorshipVulnerability {
                        pc,
                        vulnerability_type: "SignatureReuse".to_string(),
                        description: format!(
                            "Signature verification at PC {} without duplicate prevention. Same signature \
                            can be submitted multiple times. Attacker can: (1) Replay single cooperative \
                            signer's signature T times to reach threshold T, (2) Completely exclude unwanted \
                            signers from participation. Check if signer already signed before accepting.",
                            pc
                        ),
                        confidence: 0.85,
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

    fn detect_unvalidated_signers(&self) -> Vec<ThresholdCensorshipVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for ecrecover usage
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                let window_end = (pc + 80).min(self.bytecode.len());
                let mut found_ecrecover = false;
                let mut has_allowlist_check = false;
                
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA { // STATICCALL
                        found_ecrecover = true;
                        
                        // Check if recovered address is validated against allowlist
                        // Pattern: SLOAD (load allowed signers), then EQ (check membership)
                        let validation_end = (check_pc + 50).min(self.bytecode.len());
                        let validation_window = &self.bytecode[(check_pc + 1)..validation_end];
                        
                        // Count SLOADs (checking mapping/array of allowed signers)
                        let sload_count = validation_window.iter().filter(|&&b| b == 0x54).count();
                        let has_comparison = validation_window.iter().any(|&b| b == 0x14); // EQ
                        
                        has_allowlist_check = sload_count >= 1 && has_comparison;
                        break;
                    }
                }
                
                if found_ecrecover && !has_allowlist_check {
                    vulns.push(ThresholdCensorshipVulnerability {
                        pc,
                        vulnerability_type: "UnvalidatedSigner".to_string(),
                        description: format!(
                            "Signature recovery at PC {} accepts any valid signer. Without allowlist validation, \
                            attacker can: (1) Add arbitrary signers to reach threshold, (2) Dilute legitimate \
                            signers' voting power, (3) Execute with unauthorized signer set. \
                            Verify recovered address is in approved signer set.",
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
}
