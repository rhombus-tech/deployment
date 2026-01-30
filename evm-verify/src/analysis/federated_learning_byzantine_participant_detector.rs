use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedLearningVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FederatedLearningByzantineParticipantDetector {
    bytecode: Vec<u8>,
}

impl FederatedLearningByzantineParticipantDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FederatedLearningVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unverified_update_aggregation());
        vulnerabilities.extend(self.detect_sybil_attack_on_voting());
        vulnerabilities.extend(self.detect_model_inversion_privacy_leak());

        vulnerabilities
    }

    fn detect_unverified_update_aggregation(&self) -> Vec<FederatedLearningVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x01 || opcode == 0x04 { // ADD, DIV (aggregating updates)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_multiple_updates = window.iter().filter(|&&b| b == 0x35).count() >= 2; // Multiple CALLDATALOAD
                
                if has_multiple_updates {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_byzantine_robustness = forward.iter().any(|&b| b == 0x04); // DIV (median/trimmed mean)
                    let has_outlier_removal = forward.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    let has_contribution_limit = window.iter().any(|&b| b == 0x33); // CALLER (per-participant limit)
                    
                    if !has_byzantine_robustness || !has_outlier_removal || !has_contribution_limit {
                        vulns.push(FederatedLearningVulnerability {
                            pc,
                            vulnerability_type: "UnverifiedUpdateAggregation".to_string(),
                            description: format!(
                                "Federated learning aggregation at PC {} uses naive averaging without Byzantine fault tolerance. \
                                Attack: malicious participants submit extreme updates, poisoning global model. Standard mean \
                                aggregation fails with >0 Byzantine participants. Missing: Byzantine-robust aggregation (Krum, \
                                trimmed mean, median), outlier filtering, per-participant contribution caps. Should tolerate \
                                up to f Byzantine participants out of n total.",
                                pc
                            ),
                            confidence: 0.89,
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

    fn detect_sybil_attack_on_voting(&self) -> Vec<FederatedLearningVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (recording participant contribution)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_participant_id = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_participant_id {
                    let has_stake_requirement = window.iter().any(|&b| matches!(b, 0x31 | 0x54)); // BALANCE, SLOAD
                    let has_reputation_weight = window.iter().any(|&b| b == 0x02); // MUL (weighting)
                    let has_identity_verification = window.iter().any(|&b| b == 0x01); // ECRECOVER
                    
                    if !has_stake_requirement || !has_reputation_weight || !has_identity_verification {
                        vulns.push(FederatedLearningVulnerability {
                            pc,
                            vulnerability_type: "SybilAttackOnVoting".to_string(),
                            description: format!(
                                "Participant registration at PC {} vulnerable to Sybil attacks. Attacker creates multiple \
                                identities to gain outsized influence on model updates. Each identity votes/contributes equally, \
                                enabling majority attack with single entity. Missing: stake-weighted contributions, reputation-based \
                                weighting, identity verification. Should require economic commitment or proof-of-unique-human to \
                                prevent Sybil dominance.",
                                pc
                            ),
                            confidence: 0.86,
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

    fn detect_model_inversion_privacy_leak(&self) -> Vec<FederatedLearningVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (publishing model updates)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_gradient_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_model_weights = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_gradient_data || has_model_weights {
                    let has_differential_privacy = window.iter().any(|&b| b == 0x02); // MUL (noise addition)
                    let has_gradient_clipping = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_secure_aggregation = window.iter().any(|&b| b == 0x20); // KECCAK256 (encryption)
                    
                    if !has_differential_privacy || !has_gradient_clipping || !has_secure_aggregation {
                        vulns.push(FederatedLearningVulnerability {
                            pc,
                            vulnerability_type: "ModelInversionPrivacyLeak".to_string(),
                            description: format!(
                                "Model update publication at PC {} leaks training data via model inversion. Gradients/weights \
                                contain information about participant's private training data. Attack: reconstruct training examples \
                                from published updates. Missing: differential privacy noise addition, gradient clipping, secure \
                                multi-party aggregation. Raw gradient publication enables privacy attacks extracting sensitive data.",
                                pc
                            ),
                            confidence: 0.84,
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
