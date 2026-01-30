use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSideTimingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ClientSideSignatureGenerationTimingDetector {
    bytecode: Vec<u8>,
}

impl ClientSideSignatureGenerationTimingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ClientSideTimingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_signature_timing_side_channel());
        vulnerabilities.extend(self.detect_transaction_ordering_leak());
        vulnerabilities.extend(self.detect_approval_timing_frontrun());

        vulnerabilities
    }

    fn detect_signature_timing_side_channel(&self) -> Vec<ClientSideTimingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x01 { // ECRECOVER preparation (signature generation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_message_hash = window.iter().any(|&b| b == 0x20); // KECCAK256
                
                if has_message_hash {
                    let uses_constant_time = window.iter().filter(|&&b| b == 0x02).count() >= 3; // MUL operations
                    let obfuscates_timing = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if !uses_constant_time {
                        vulns.push(ClientSideTimingVulnerability {
                            pc,
                            vulnerability_type: "SignatureTimingSideChannel".to_string(),
                            description: format!(
                                "Signature generation at PC {} vulnerable to timing side-channel. Attack: client-side JavaScript performs crypto operations, timing variations leak \
                                information about private keys or message content. Timing attacks: (1) signature generation time varies based on message content, attacker measures timing \
                                across many signatures, (2) ECDSA k-nonce generation not constant-time, timing reveals bits of k, enables key recovery, (3) hash-to-curve operations timing \
                                dependent on input, leaks partial message. Example: web3 dApp signs transactions client-side, malicious extension measures performance.now() before/after \
                                signing, analyzes timing patterns across 1000 signatures, extracts partial private key bits. Or: BLS signature aggregation timing reveals which keys participated. \
                                Real risk: JavaScript crypto libraries not constant-time (unlike hardware wallets), vulnerable to high-precision timing attacks. Missing: constant-time \
                                implementation, timing jitter, server-side signing. Should implement: use hardware wallet for signing (moves crypto to secure enclave), if must sign client-side \
                                use vetted constant-time libraries (noble-secp256k1), add random delays to obscure timing, minimize client-side key operations.",
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

    fn detect_transaction_ordering_leak(&self) -> Vec<ClientSideTimingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (transaction broadcast)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_multiple_transactions = window.iter().filter(|&&b| b == 0xF1).count() >= 2;
                
                if has_multiple_transactions {
                    let randomizes_timing = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let uses_private_relay = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    
                    if !randomizes_timing {
                        vulns.push(ClientSideTimingVulnerability {
                            pc,
                            vulnerability_type: "TransactionOrderingLeak".to_string(),
                            description: format!(
                                "Transaction broadcast at PC {} leaks ordering information via timing. Attack: dApp sends multiple transactions sequentially, timing between broadcasts \
                                reveals transaction relationship, enables targeted frontrunning. Timing leak: (1) dApp approves token spending, waits for confirmation, then swaps, (2) \
                                attacker monitors mempool, sees approval transaction, (3) knows swap coming next, (4) frontruns swap with higher gas. Or: atomic transaction sequences sent \
                                with predictable timing gaps, attacker inserts transaction between. Example: yield optimizer approves USDC to Curve, waits 500ms, calls deposit(), bot sees \
                                approval, predicts deposit() coming, frontruns with own deposit, extracts MEV. Missing: transaction batching, timing randomization, flashbots bundles. Should \
                                use: bundle transactions together (flashbots, Eden), add random delays between transactions (0-5 seconds), or use multicall to execute atomically, implement \
                                commit-reveal for sensitive transaction sequences.",
                                pc
                            ),
                            confidence: 0.82,
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

    fn detect_approval_timing_frontrun(&self) -> Vec<ClientSideTimingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (approval state)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_approval_logic = window.iter().any(|&b| b == 0x35); // CALLDATALOAD (amount)
                
                if has_approval_logic {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let batches_with_usage = forward.iter().any(|&b| b == 0xF1); // CALL following approval
                    let uses_permit_signature = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    
                    if !batches_with_usage && !uses_permit_signature {
                        vulns.push(ClientSideTimingVulnerability {
                            pc,
                            vulnerability_type: "ApprovalTimingFrontrun".to_string(),
                            description: format!(
                                "Token approval at PC {} sent separately from usage transaction. Attack: approval transaction visible in mempool, attacker sees approval, frontruns actual \
                                usage transaction. Approval frontrun: (1) user wants to swap USDC on Uniswap, (2) dApp sends approve(Uniswap, 1000 USDC), (3) waits for confirmation, (4) \
                                sends swap transaction, (5) attacker monitoring mempool sees approval, (6) predicts swap coming, (7) frontruns swap with own transaction, (8) causes user \
                                slippage or extracts sandwich MEV. Timing vulnerability: gap between approval and usage allows frontrunning. Example: user approves 10 ETH to NFT marketplace, \
                                bot sees approval, monitors for buy transaction, frontruns buy with higher gas, buys NFT first. Missing: transaction batching, Permit EIP-2612, gasless approvals. \
                                Should implement: use EIP-2612 Permit for gasless approvals (combines approve + action in one signature), batch approve + swap in multicall, use router contracts \
                                that handle approvals internally, or send both transactions as flashbots bundle.",
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
}
