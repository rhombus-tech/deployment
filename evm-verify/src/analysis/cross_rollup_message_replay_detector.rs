use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRollupReplayVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossRollupMessageReplayDetector {
    bytecode: Vec<u8>,
}

impl CrossRollupMessageReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CrossRollupReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_chain_id_validation());
        vulnerabilities.extend(self.detect_nonce_reuse_across_chains());
        vulnerabilities.extend(self.detect_signature_replay_cross_rollup());

        vulnerabilities
    }

    fn detect_missing_chain_id_validation(&self) -> Vec<CrossRollupReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x01 { // ECRECOVER (signature verification)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_message_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_message_data {
                    let has_chain_id = window.iter().any(|&b| b == 0x46); // CHAINID
                    let has_domain_separator = window.iter().any(|&b| b == 0x20); // KECCAK256 (EIP-712 domain)
                    
                    if !has_chain_id && !has_domain_separator {
                        vulns.push(CrossRollupReplayVulnerability {
                            pc,
                            vulnerability_type: "MissingChainIdValidation".to_string(),
                            description: format!(
                                "Cross-rollup message at PC {} without chain ID binding. Signature valid on Optimism can be replayed \
                                on Arbitrum, Base, etc. Attack: user signs message on rollup A, attacker replays on rollup B where \
                                user has different assets/state. Missing: CHAINID in signature hash, EIP-712 domain separator with \
                                chain ID. Messages should be bound to specific rollup to prevent cross-chain replay.",
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

    fn detect_nonce_reuse_across_chains(&self) -> Vec<CrossRollupReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (loading nonce)
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_user_address = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_user_address {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_nonce_increment = forward.iter().any(|&b| b == 0x01); // ADD
                    let has_nonce_check = forward.iter().any(|&b| b == 0x14); // EQ
                    
                    if has_nonce_increment && has_nonce_check {
                        let has_chain_specific_nonce = window.iter().any(|&b| b == 0x46); // CHAINID
                        
                        if !has_chain_specific_nonce {
                            vulns.push(CrossRollupReplayVulnerability {
                                pc,
                                vulnerability_type: "NonceReuseAcrossChains".to_string(),
                                description: format!(
                                    "Nonce management at PC {} uses global counter without chain distinction. Same nonce value exists \
                                    on multiple rollups. Attack: execute transaction on rollup A (nonce N), replay same signed transaction \
                                    on rollup B (also nonce N). Missing: chain-specific nonce storage, nonce namespacing by chain ID. \
                                    Nonces should be independent per rollup to prevent replay.",
                                    pc
                                ),
                                confidence: 0.87,
                            });
                        }
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

    fn detect_signature_replay_cross_rollup(&self) -> Vec<CrossRollupReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (storing used signature)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_signature_hash = window.iter().any(|&b| b == 0x20); // KECCAK256
                let has_signature_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_signature_hash && has_signature_data {
                    let has_rollup_identifier = window.iter().any(|&b| b == 0x46); // CHAINID
                    let has_contract_address = window.iter().any(|&b| b == 0x30); // ADDRESS
                    
                    if !has_rollup_identifier || !has_contract_address {
                        vulns.push(CrossRollupReplayVulnerability {
                            pc,
                            vulnerability_type: "SignatureReplayCrossRollup".to_string(),
                            description: format!(
                                "Signature tracking at PC {} without rollup/contract binding. Signature marked used on one rollup \
                                but can be replayed on another. Attack: sign permit on Optimism, signature marked used there, but \
                                replay on Arbitrum where same contract deployed at same address. Missing: signature hash includes \
                                CHAINID and contract ADDRESS. Signature usage should be tracked per-rollup per-contract.",
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
