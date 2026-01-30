use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSigCoordinationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MultiSigCoordinationFailureDetector {
    bytecode: Vec<u8>,
}

impl MultiSigCoordinationFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MultiSigCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_signature_reuse_attack());
        vulnerabilities.extend(self.detect_threshold_manipulation());
        vulnerabilities.extend(self.detect_signer_collusion_risk());

        vulnerabilities
    }

    fn detect_signature_reuse_attack(&self) -> Vec<MultiSigCoordinationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x01 { // ECRECOVER (signature verification)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_multisig_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_multisig_data {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_nonce = window.iter().any(|&b| b == 0x54); // SLOAD (transaction nonce)
                    let has_signature_hash = forward.iter().any(|&b| b == 0x20); // KECCAK256
                    let has_used_signature_check = forward.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !has_nonce || !has_signature_hash || !has_used_signature_check {
                        vulns.push(MultiSigCoordinationVulnerability {
                            pc,
                            vulnerability_type: "SignatureReuseAttack".to_string(),
                            description: format!(
                                "Multi-sig verification at PC {} vulnerable to signature replay. Signers' signatures can be reused \
                                for different transactions. Attack: collect M-of-N signatures for transaction A, replay same signatures \
                                for transaction B with different parameters. Missing: nonce in signed message, signature hash tracking, \
                                transaction-specific commitment. Each signature should be bound to specific transaction data.",
                                pc
                            ),
                            confidence: 0.90,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_threshold_manipulation(&self) -> Vec<MultiSigCoordinationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (updating threshold)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_threshold_value = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_threshold_value {
                    let has_multisig_approval = window.iter().filter(|&&b| b == 0x01).count() >= 2; // Multiple ECRECOVER
                    let has_bounds_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_signer_count_check = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !has_multisig_approval || !has_bounds_check || !has_signer_count_check {
                        vulns.push(MultiSigCoordinationVulnerability {
                            pc,
                            vulnerability_type: "ThresholdManipulation".to_string(),
                            description: format!(
                                "Multi-sig threshold update at PC {} insufficiently protected. Attack: compromised signer changes M-of-N \
                                threshold to 1-of-N, enabling unilateral control. Or reduces M too low for security. Missing: higher \
                                threshold for threshold changes (e.g., unanimous or 2/3+), minimum M validation (e.g., M >= N/2), \
                                separate admin role. Threshold modifications should require stronger consensus than normal operations.",
                                pc
                            ),
                            confidence: 0.88,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_signer_collusion_risk(&self) -> Vec<MultiSigCoordinationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x01 { // ECRECOVER (signature verification)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let window_end = (pc + 100).min(self.bytecode.len());
                let forward = &self.bytecode[pc..window_end];
                
                let signature_count = forward.iter().filter(|&&b| b == 0x01).count();
                
                if signature_count >= 2 {
                    let has_timelock = forward.iter().any(|&b| b == 0x42); // TIMESTAMP (delay)
                    let has_public_proposal = forward.iter().any(|&b| matches!(b, 0xA0..=0xA4)); // LOG (transparency)
                    let has_veto_mechanism = forward.iter().filter(|&&b| b == 0x57).count() >= 2;
                    
                    if !has_timelock && !has_public_proposal && !has_veto_mechanism {
                        vulns.push(MultiSigCoordinationVulnerability {
                            pc,
                            vulnerability_type: "SignerCollusionRisk".to_string(),
                            description: format!(
                                "Multi-sig at PC {} allows immediate execution after threshold met. Colluding signers can execute \
                                malicious transaction instantly without oversight. Attack: M colluding signers coordinate off-chain, \
                                submit signatures simultaneously, drain funds. Missing: timelock delay (e.g., 48 hours), public proposal \
                                period, veto mechanism for remaining signers. Should provide transparency and intervention window.",
                                pc
                            ),
                            confidence: 0.85,
                        });
                    }
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
