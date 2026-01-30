use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossDomainMessageReplayVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossDomainMessageReplayDetector {
    bytecode: Vec<u8>,
}

impl CrossDomainMessageReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CrossDomainMessageReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_missing_nonce_in_bridge_message());
        vulnerabilities.extend(self.detect_cross_chain_replay_no_chain_id());
        vulnerabilities.extend(self.detect_message_hash_collision());
        vulnerabilities.extend(self.detect_relayer_replay_attack());
        vulnerabilities
    }

    fn detect_missing_nonce_in_bridge_message(&self) -> Vec<CrossDomainMessageReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (message hashing for bridge)
                let window_end = (pc + 120).min(self.bytecode.len());
                let has_external_call = self.bytecode[pc..window_end].iter().any(|&b| matches!(b, 0xF1 | 0xF4));
                if has_external_call {
                    let start = if pc > 100 { pc - 100 } else { 0 };
                    let has_nonce = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x54).count() >= 2;
                    if !has_nonce {
                        vulns.push(CrossDomainMessageReplayVulnerability {
                            pc,
                            vulnerability_type: "MissingNonceInBridgeMessage".to_string(),
                            description: format!("Cross-domain message hash at PC {} lacks nonce inclusion for replay protection. Attack: bridge message sent from L1 to L2 without unique nonce, attacker captures message, replays same message multiple times on destination chain, executes same action repeatedly (e.g., mint tokens multiple times for single deposit). Real vulnerability: cross-domain messages (L1↔L2, chain A↔chain B) must be uniquely identified, without nonce same message payload replays unlimited times. Example: user deposits 100 ETH on L1 to mint wrapped tokens on L2, bridge emits message mint(user, 100), message doesn't include nonce, attacker replays message 10 times, user receives 1000 wrapped tokens for 100 ETH deposit, bridge insolvent. Missing: monotonic nonce in message hash, nonce verification on destination. Should include: message_hash = keccak256(source_chain, dest_chain, nonce, sender, data). Fix: add per-sender nonce counter on source chain, increment nonce for each message, include nonce in message hash, verify nonce on destination (must be exactly next_expected_nonce), store processed nonces in mapping to prevent re-execution, implement nonce gap handling (allow processing out-of-order but track gaps), add nonce synchronization between chains.", pc),
                            confidence: 0.86,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_cross_chain_replay_no_chain_id(&self) -> Vec<CrossDomainMessageReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (message hashing)
                let start = if pc > 150 { pc - 150 } else { 0 };
                let has_chainid = self.bytecode[start..pc].iter().any(|&b| b == 0x46);
                if !has_chainid {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let looks_like_bridge = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0xF1).count() >= 1;
                    if looks_like_bridge {
                        vulns.push(CrossDomainMessageReplayVulnerability {
                            pc,
                            vulnerability_type: "CrossChainReplayNoChainId".to_string(),
                            description: format!("Message hash at PC {} excludes chain ID, enabling cross-chain replay attacks. Attack: message sent from chain A to chain B, attacker replays same signed message on chain C (with identical contract), message valid because signature doesn't commit to destination chain, unauthorized execution on chain C. Real vulnerability: multi-chain deployments (same contract on Ethereum, Polygon, Arbitrum, etc.) vulnerable if messages don't include chain ID in signature, EIP-712 requires chain ID but often omitted in custom bridge protocols. Example: user approves withdraw from Arbitrum bridge (chain ID 42161), signs message mint(user, 100, Arbitrum), attacker captures signature, replays on Optimism bridge (same contract address due to CREATE2), Optimism bridge accepts signature (doesn't verify chain ID), mints tokens on Optimism without corresponding deposit. Missing: source_chain_id and dest_chain_id in message hash, CHAINID opcode usage. Should include: keccak256(source_chain_id, dest_chain_id, ...). Fix: include both source and destination chain IDs in message hash (msg_hash = keccak256(CHAINID, dest_chain_id, nonce, data)), verify on destination that dest_chain_id == block.chainid, implement EIP-712 domain separator with chain ID, add chain-specific message registries (messages on chain A cannot execute on chain B even with replay), use different contract addresses per chain (prevents cross-chain signature replay).", pc),
                            confidence: 0.84,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_message_hash_collision(&self) -> Vec<CrossDomainMessageReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_dynamic_length = self.bytecode[start..pc].iter().filter(|&&b| b == 0x51 || b == 0x35).count() >= 1;
                if has_dynamic_length {
                    let has_length_prefix = self.bytecode[start..pc].iter().filter(|&&b| b == 0x52).count() >= 1;
                    if !has_length_prefix {
                        vulns.push(CrossDomainMessageReplayVulnerability {
                            pc,
                            vulnerability_type: "MessageHashCollision".to_string(),
                            description: format!("Message hash at PC {} uses dynamic data without length encoding, enabling collision attacks. Attack: two different messages hash to same value due to improper encoding, attacker crafts message B with same hash as legitimate message A, replays authorization from message A to execute message B. Real vulnerability: keccak256(abi.encodePacked(dynamic_array1, dynamic_array2)) allows collisions, [0x1234] + [0x5678] hashes same as [0x12] + [0x345678] due to concatenation ambiguity. Example: legitimate message: withdraw(recipient=[0x1111], amount=[100,200]), hash H1, attacker crafts withdraw(recipient=[0x11], amount=[17,100,200]) which produces same hash H1 because abi.encodePacked concatenates without boundaries, replays approval for first message to execute second message with different recipient. Missing: abi.encode (not encodePacked), length prefixes for dynamic types. Should use: keccak256(abi.encode(...)) with proper type encoding. Fix: use abi.encode instead of abi.encodePacked for message hashing (includes type information and length prefixes), explicitly encode array lengths before data (hash = keccak256(length1, data1, length2, data2)), add type tags to differentiate message structures, use EIP-712 structured data hashing (prevents ambiguity), verify message hash uniqueness before processing, implement collision detection (reject if hash seen with different message data).", pc),
                            confidence: 0.80,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_relayer_replay_attack(&self) -> Vec<CrossDomainMessageReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (relayer execution)
                let start = if pc > 150 { pc - 150 } else { 0 };
                let has_message_hash_check = self.bytecode[start..pc].iter().any(|&b| b == 0x20);
                if has_message_hash_check {
                    let has_processed_flag = self.bytecode[start..pc].iter().filter(|&&b| b == 0x55).count() >= 1;
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let checks_processed = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x54).count() >= 2;
                    if !has_processed_flag || !checks_processed {
                        vulns.push(CrossDomainMessageReplayVulnerability {
                            pc,
                            vulnerability_type: "RelayerReplayAttack".to_string(),
                            description: format!("Message execution at PC {} lacks processed message tracking for relayer submissions. Attack: relayer submits bridge message, message executes successfully, same relayer (or different relayer) resubmits identical message, no check for previous execution, message processes again, double-spend or double-action. Real vulnerability: decentralized relayers can submit messages multiple times if contract doesn't track processed messages, even with nonces attacker might replay if nonce tracking has gaps. Example: user deposits 50 DAI on Ethereum for L2 transfer, relayer A submits message to L2, 50 DAI minted on L2, relayer B finds same message in L1 events, submits again, another 50 DAI minted (total 100 for 50 deposit), bridge insolvent. Missing: processed message hash registry, idempotency checks. Should implement: mapping(bytes32 => bool) processedMessages; require(!processedMessages[msgHash]). Fix: maintain processed message hash mapping (bytes32 msg_hash => bool processed), check mapping before execution (require(!processedMessages[msg_hash], 'already processed')), set flag after successful execution (processedMessages[msg_hash] = true), add execution receipts with merkle tree for light client verification, implement two-phase commit (mark processing, then confirm), allow message cancellation window before finalization, emit events with message hash for off-chain tracking.", pc),
                            confidence: 0.83,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
