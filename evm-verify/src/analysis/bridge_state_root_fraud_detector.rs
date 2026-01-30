use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeStateRootVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BridgeStateRootFraudDetector {
    bytecode: Vec<u8>,
}

impl BridgeStateRootFraudDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BridgeStateRootVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unverified_state_root());
        vulnerabilities.extend(self.detect_merkle_proof_manipulation());
        vulnerabilities.extend(self.detect_finality_assumption_bypass());

        vulnerabilities
    }

    fn detect_unverified_state_root(&self) -> Vec<BridgeStateRootVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (storing state root)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_state_root = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_state_root {
                    let has_signature_check = window.iter().any(|&b| b == 0x01); // ECRECOVER
                    let has_multisig = window.iter().filter(|&&b| b == 0x01).count() >= 3;
                    let has_fraud_proof = window.iter().any(|&b| b == 0x43); // NUMBER (challenge period)
                    
                    if !has_signature_check || !has_multisig || !has_fraud_proof {
                        vulns.push(BridgeStateRootVulnerability {
                            pc,
                            vulnerability_type: "UnverifiedStateRoot".to_string(),
                            description: format!(
                                "State root update at PC {} without sufficient verification. Malicious relayer can submit invalid \
                                state root, enabling fake withdrawal proofs. Attack: submit fraudulent L2 state root to L1, prove \
                                non-existent withdrawals, steal bridge funds. Missing: multi-signature requirement (M-of-N validators), \
                                fraud proof challenge window, ZK proof of state transition. Single relayer should not control state roots.",
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

    fn detect_merkle_proof_manipulation(&self) -> Vec<BridgeStateRootVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (merkle proof verification)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_proof_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_proof_data {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_root_comparison = forward.iter().any(|&b| b == 0x14); // EQ
                    
                    if has_root_comparison {
                        let has_depth_validation = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                        let has_leaf_uniqueness = forward.iter().filter(|&&b| b == 0x20).count() >= 2;
                        
                        if !has_depth_validation || !has_leaf_uniqueness {
                            vulns.push(BridgeStateRootVulnerability {
                                pc,
                                vulnerability_type: "MerkleProofManipulation".to_string(),
                                description: format!(
                                    "Merkle proof verification at PC {} vulnerable to manipulation. Attack vectors: (1) malformed proof \
                                    with excessive depth causing DoS, (2) duplicate leaf nodes enabling double-withdrawal, (3) proof \
                                    path collision. Missing: maximum proof depth limit, leaf index validation, proof path uniqueness check. \
                                    Weak verification allows proving false inclusion in merkle tree.",
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

    fn detect_finality_assumption_bypass(&self) -> Vec<BridgeStateRootVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (reading state root)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_withdrawal = window.iter().any(|&b| matches!(b, 0xF1 | 0x55)); // CALL or SSTORE (withdrawal processing)
                
                if has_withdrawal {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_finality_delay = pre_window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_reorg_protection = pre_window.iter().any(|&b| b == 0x43); // NUMBER (block confirmations)
                    
                    if !has_finality_delay || !has_reorg_protection {
                        vulns.push(BridgeStateRootVulnerability {
                            pc,
                            vulnerability_type: "FinalityAssumptionBypass".to_string(),
                            description: format!(
                                "State root usage at PC {} assumes immediate finality. On optimistic rollups or PoS chains, state can \
                                reorg. Attack: submit withdrawal proof using recent state root, state reorgs on source chain, withdrawal \
                                executes on destination with invalid state. Missing: minimum finality delay (e.g., 7 days for optimistic), \
                                reorg detection, checkpoint age validation. Must wait for source chain finality before trusting state roots.",
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
