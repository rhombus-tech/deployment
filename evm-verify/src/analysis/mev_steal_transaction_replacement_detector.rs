use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevStealVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MevStealTransactionReplacementDetector {
    bytecode: Vec<u8>,
}

impl MevStealTransactionReplacementDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MevStealVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_replicate_and_replace());
        vulnerabilities.extend(self.detect_searcher_transaction_theft());
        vulnerabilities.extend(self.detect_private_transaction_leak());

        vulnerabilities
    }

    fn detect_replicate_and_replace(&self) -> Vec<MevStealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x33 { // CALLER
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_authorization = window.iter().any(|&b| b == 0x14); // EQ (caller check)
                let has_arbitrage_logic = window.iter().filter(|&&b| matches!(b, 0xF1 | 0xFA)).count() >= 2; // Multiple CALLs
                
                if has_arbitrage_logic && !has_authorization {
                    let has_signature = window.iter().any(|&b| b == 0x20); // KECCAK256
                    
                    if !has_signature {
                        vulns.push(MevStealVulnerability {
                            pc,
                            vulnerability_type: "ReplicateAndReplace".to_string(),
                            description: format!(
                                "Open arbitrage function at PC {} allows transaction replication. MEV steal attack: searcher submits profitable arbitrage tx to public \
                                mempool, builder/validator observes tx, replicates exact calldata but changes tx.origin/msg.sender to their own address, includes \
                                replicated tx instead of original, steals searcher's MEV profit. Missing: transaction signature verification, searcher address validation, \
                                commit-reveal for trade details. Should require: signed payload with nonce or use private transaction pools (Flashbots).",
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

    fn detect_searcher_transaction_theft(&self) -> Vec<MevStealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (swap execution)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_swap_params = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_recipient = window.iter().any(|&b| b == 0x33); // CALLER or parameter
                
                if has_swap_params {
                    let has_recipient_validation = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ checks
                    let has_nonce = window.iter().any(|&b| b == 0x54); // SLOAD (nonce)
                    
                    if !has_recipient_validation && !has_nonce {
                        vulns.push(MevStealVulnerability {
                            pc,
                            vulnerability_type: "SearcherTransactionTheft".to_string(),
                            description: format!(
                                "Swap at PC {} allows recipient substitution. Attack: searcher finds profitable DEX arbitrage, submits tx with recipient = searcher address, \
                                validator modifies recipient parameter in calldata to validator's address, tx still valid and executes, profits go to validator not \
                                searcher. Transaction parameter injection. Missing: cryptographic binding of recipient to transaction, signed intent with recipient \
                                included, atomic transfer to msg.sender only. Should enforce: recipient must be msg.sender or signed in payload.",
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

    fn detect_private_transaction_leak(&self) -> Vec<MevStealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_sensitive_data = window.iter().filter(|&&b| b == 0x35).count() >= 3; // Multiple params
                let has_execution_logic = window.iter().any(|&b| matches!(b, 0xF1 | 0xF4)); // CALL, DELEGATECALL
                
                if has_sensitive_data && has_execution_logic {
                    let has_encryption = window.iter().any(|&b| b == 0x20); // KECCAK256 (but not real encryption)
                    let has_commitment = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !has_commitment {
                        vulns.push(MevStealVulnerability {
                            pc,
                            vulnerability_type: "PrivateTransactionLeak".to_string(),
                            description: format!(
                                "Sensitive transaction data at PC {} transmitted in cleartext. Attack: searcher uses 'private' RPC (Flashbots Protect) to hide tx, but \
                                builder is malicious or compromised, builder extracts strategy from tx data, front-runs with own similar tx, or sells information to other \
                                searchers. Private pool doesn't guarantee transaction privacy from builder. Missing: threshold encryption of transaction data, SGX/TEE \
                                execution, on-chain commitment scheme. Should use: encrypted intents with decryption only after inclusion or trusted execution environment.",
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
