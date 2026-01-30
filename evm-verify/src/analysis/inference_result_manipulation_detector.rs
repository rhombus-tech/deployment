use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceManipulationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct InferenceResultManipulationDetector {
    bytecode: Vec<u8>,
}

impl InferenceResultManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<InferenceManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_oracle_result_tampering());
        vulnerabilities.extend(self.detect_off_chain_computation_trust());
        vulnerabilities.extend(self.detect_result_caching_manipulation());

        vulnerabilities
    }

    fn detect_oracle_result_tampering(&self) -> Vec<InferenceManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xFA | 0xF1) { // ML inference oracle call
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_oracle_address = window.windows(2).any(|w| w[0] >= 0x73 && w[0] <= 0x7F); // PUSH20
                
                if has_oracle_address {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_signature_verification = forward.iter().any(|&b| b == 0x01); // ECRECOVER
                    let has_result_hash = forward.iter().any(|&b| b == 0x20); // KECCAK256
                    let has_multiple_oracles = window.iter().filter(|&&b| matches!(b, 0xFA | 0xF1)).count() >= 2;
                    
                    if !has_signature_verification || !has_result_hash || !has_multiple_oracles {
                        vulns.push(InferenceManipulationVulnerability {
                            pc,
                            vulnerability_type: "OracleResultTampering".to_string(),
                            description: format!(
                                "ML inference oracle at PC {} without result integrity verification. Malicious or compromised \
                                oracle can return arbitrary predictions. Example: fraud detection oracle always returns \"legitimate\" \
                                for attacker's transactions. Missing: cryptographic result commitment, multi-oracle consensus, \
                                verifiable computation proof. Single oracle has complete control over inference results.",
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

    fn detect_off_chain_computation_trust(&self) -> Vec<InferenceManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (off-chain result)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_result_usage = window.iter().any(|&b| b == 0x55); // SSTORE (using result)
                let has_value_transfer = window.iter().any(|&b| matches!(b, 0xF1 | 0xF4)); // CALL, DELEGATECALL
                
                if has_result_usage || has_value_transfer {
                    let has_zk_proof = window.iter().any(|&b| b == 0x08); // bn256Pairing (ZK verification)
                    let has_fraud_proof = window.iter().any(|&b| b == 0x43); // NUMBER (challenge period)
                    let has_stake_slashing = window.iter().any(|&b| b == 0x03); // SUB (slashing)
                    
                    if !has_zk_proof && !has_fraud_proof && !has_stake_slashing {
                        vulns.push(InferenceManipulationVulnerability {
                            pc,
                            vulnerability_type: "OffChainComputationTrust".to_string(),
                            description: format!(
                                "Off-chain ML inference result at PC {} accepted without cryptographic verification. Trusting \
                                off-chain computation without proof enables result fabrication. Missing: ZK-SNARK proving correct \
                                inference execution, optimistic verification with fraud proofs, economic security via staking/slashing. \
                                No mechanism to verify computation was performed honestly on correct model with given input.",
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

    fn detect_result_caching_manipulation(&self) -> Vec<InferenceManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (cached inference result)
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_input_hash = window.iter().any(|&b| b == 0x20); // KECCAK256 (cache key)
                
                if has_input_hash {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_freshness_check = forward.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_model_version = forward.iter().any(|&b| b == 0x54); // SLOAD (version check)
                    let has_invalidation = forward.iter().any(|&b| b == 0x55); // SSTORE (cache update)
                    
                    if !has_freshness_check || !has_model_version || !has_invalidation {
                        vulns.push(InferenceManipulationVulnerability {
                            pc,
                            vulnerability_type: "ResultCachingManipulation".to_string(),
                            description: format!(
                                "Cached inference result at PC {} without staleness/validity checks. Attack: trigger inference, \
                                cache result, update model, old cached result still used for same input giving outdated predictions. \
                                Or: cache poisoning via hash collision. Missing: cache expiration timestamp, model version tracking, \
                                cache invalidation on model updates. Stale results enable exploiting outdated model behavior.",
                                pc
                            ),
                            confidence: 0.83,
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
