use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainReplayVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossChainReplayAttackDetector {
    bytecode: Vec<u8>,
}

impl CrossChainReplayAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CrossChainReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_chain_id());
        vulnerabilities.extend(self.detect_signature_replay_cross_chain());
        vulnerabilities.extend(self.detect_bridge_message_replay());

        vulnerabilities
    }

    fn detect_missing_chain_id(&self) -> Vec<CrossChainReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (signature verification)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_signature_check = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_signature_check {
                    let has_chain_id = window.iter().any(|&b| b == 0x46); // CHAINID opcode
                    let has_domain_separator = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !has_chain_id && !has_domain_separator {
                        vulns.push(CrossChainReplayVulnerability {
                            pc,
                            vulnerability_type: "MissingChainId".to_string(),
                            description: format!(
                                "Signature verification at PC {} missing chain ID. Attack: user signs transaction on Ethereum mainnet (chain ID 1), attacker replays \
                                identical signature on Polygon (chain ID 137), transaction executes on both chains, user loses funds twice. Classic cross-chain replay. \
                                EIP-155 added chain ID to prevent this but must be enforced in signature verification. Missing: CHAINID opcode in hash, EIP-712 domain \
                                separator with chain ID. Should include: keccak256(abi.encode(chainId, address(this), nonce, action)) in signed message to make signatures \
                                chain-specific and contract-specific.",
                                pc
                            ),
                            confidence: 0.91,
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

    fn detect_signature_replay_cross_chain(&self) -> Vec<CrossChainReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (nonce/execution tracking)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_ecrecover = window.windows(2).any(|w| {
                    w[0] == 0x60 && w[1] == 0x01 // PUSH1 0x01 (ecrecover precompile)
                });
                
                if has_ecrecover {
                    let has_nonce_check = window.iter().any(|&b| b == 0x54); // SLOAD (nonce)
                    let has_chain_binding = window.iter().any(|&b| b == 0x46); // CHAINID
                    
                    if has_nonce_check && !has_chain_binding {
                        vulns.push(CrossChainReplayVulnerability {
                            pc,
                            vulnerability_type: "SignatureReplayCrossChain".to_string(),
                            description: format!(
                                "Meta-transaction at PC {} vulnerable to cross-chain replay despite nonce. Attack: contract uses nonces to prevent replay on same chain, \
                                but nonce storage is separate per chain, attacker can replay signature on different chain with same nonce counter. Example: user approves \
                                spend on Ethereum with nonce=5, attacker deploys identical contract on BSC, replays signature with BSC nonce=5, drains user on both chains. \
                                Missing: chain ID in signature hash, contract address in signature, cross-chain nonce registry. Should use EIP-712 with domain separator \
                                including: chainId, verifyingContract address.",
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

    fn detect_bridge_message_replay(&self) -> Vec<CrossChainReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (bridge message execution)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_message_hash = window.iter().any(|&b| b == 0x20); // KECCAK256
                let has_message_execution = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_message_hash && has_message_execution {
                    let has_message_id_storage = window.iter().filter(|&&b| b == 0x55).count() >= 2;
                    let has_source_chain_check = window.iter().any(|&b| b == 0x35); // CALLDATALOAD (source chain)
                    
                    if !has_message_id_storage {
                        vulns.push(CrossChainReplayVulnerability {
                            pc,
                            vulnerability_type: "BridgeMessageReplay".to_string(),
                            description: format!(
                                "Bridge message execution at PC {} lacks replay protection. Attack: canonical bridge relays message from L1 to L2, message executed, \
                                attacker captures message data, replays message to bridge again, message executes twice. Example: withdraw 100 ETH from L2 to L1, bridge \
                                processes, attacker replays withdraw message, gets another 100 ETH. Missing: executed message ID tracking, nonce per source chain, \
                                message hash storage. Should implement: mapping(bytes32 messageHash => bool executed) and check before execution, include source chain ID + \
                                nonce in message hash to prevent cross-rollup replay.",
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
}
