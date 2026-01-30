use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TornadoCashNovaVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TornadoCashNovaShieldedPoolLinkabilityDetector {
    bytecode: Vec<u8>,
}

impl TornadoCashNovaShieldedPoolLinkabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TornadoCashNovaVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_nullifier_set_linkability());
        vulnerabilities.extend(self.detect_amount_correlation_leak());
        vulnerabilities.extend(self.detect_deposit_withdrawal_timing_correlation());

        vulnerabilities
    }

    fn detect_nullifier_set_linkability(&self) -> Vec<TornadoCashNovaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (nullifier storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_nullifier_hash = window.iter().any(|&b| b == 0x20); // KECCAK256
                let has_commitment_check = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_nullifier_hash {
                    let has_anonymity_set_mixing = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    let has_decoy_nullifiers = window.iter().filter(|&&b| b == 0x55).count() >= 3;
                    
                    if !has_anonymity_set_mixing && !has_decoy_nullifiers {
                        vulns.push(TornadoCashNovaVulnerability {
                            pc,
                            vulnerability_type: "NullifierSetLinkability".to_string(),
                            description: format!(
                                "Tornado Cash Nova nullifier at PC {} vulnerable to set linkability. Attack: shielded pool uses nullifiers to prevent double-spending, \
                                but nullifier set can be analyzed to link deposits/withdrawals. If nullifier derived deterministically from note commitment without blinding, \
                                adversary monitoring chain observes: (1) deposit creates commitment C, (2) withdrawal reveals nullifier N = hash(C), (3) links deposit to \
                                withdrawal. Breaks anonymity. Example: user deposits 100 ETH, nullifier reveals it's same user who deposited earlier, deanonymizes transaction \
                                graph. Missing: nullifier blinding with random salt, decoy nullifiers to enlarge anonymity set, zero-knowledge proof that nullifier valid without \
                                revealing commitment. Should use: nullifier = hash(commitment || randomness || secret), post multiple decoy nullifiers per real withdrawal.",
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

    fn detect_amount_correlation_leak(&self) -> Vec<TornadoCashNovaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (withdrawal)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_amount_transfer = window.iter().any(|&b| b == 0x35); // CALLDATALOAD (amount)
                let has_zk_proof = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                
                if has_amount_transfer && has_zk_proof {
                    let has_fixed_denomination = window.iter().filter(|&&b| b == 0x14).count() >= 2; // EQ checks
                    let has_amount_hiding = window.iter().filter(|&&b| b == 0x02).count() >= 3; // MUL (blinding)
                    
                    if !has_amount_hiding {
                        vulns.push(TornadoCashNovaVulnerability {
                            pc,
                            vulnerability_type: "AmountCorrelationLeak".to_string(),
                            description: format!(
                                "Shielded withdrawal at PC {} leaks amount correlation. Attack: Nova allows variable amounts unlike fixed-denomination Tornado Classic, but \
                                if amounts not properly blinded, statistical analysis can correlate deposits and withdrawals. Example: user deposits exactly 12.3456 ETH, later \
                                withdraws 12.3456 ETH, unique amount links transactions even with different addresses. Amount becomes identifying metadata. Also vulnerable to: \
                                timing correlation (deposit 10 ETH, withdraw 10 ETH 5 minutes later), round number analysis (amounts like 1.0, 5.0, 10.0 more common), statistical \
                                clustering. Missing: Pedersen commitment to hide amounts, range proofs for encrypted amounts, amount mixing/splitting. Should implement: commit to \
                                amount with randomness, prove amount in valid range without revealing, or use fixed denominations with change addresses.",
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

    fn detect_deposit_withdrawal_timing_correlation(&self) -> Vec<TornadoCashNovaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_withdrawal_logic = window.iter().any(|&b| b == 0xF1); // CALL
                let has_proof_verification = window.iter().any(|&b| b == 0xFA); // STATICCALL
                
                if has_withdrawal_logic && has_proof_verification {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_delay_enforcement = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    let has_min_anonymity_set = pre_window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_delay_enforcement {
                        vulns.push(TornadoCashNovaVulnerability {
                            pc,
                            vulnerability_type: "DepositWithdrawalTimingCorrelation".to_string(),
                            description: format!(
                                "Privacy pool withdrawal at PC {} allows immediate withdrawal enabling timing correlation. Attack: user deposits and immediately withdraws, \
                                temporal proximity reveals linkage. Adversary monitors mempool/chain: deposit in block N, withdrawal in block N+1, high probability same user. \
                                Timing analysis combined with amount analysis breaks anonymity set. Example: deposit 5.5 ETH at timestamp T, withdraw 5.5 ETH at T+30sec, \
                                obvious correlation. Real-world: Chainalysis uses timing + amount heuristics to deanonymize Tornado users. Missing: mandatory delay period \
                                (e.g., 24 hours minimum), anonymity set size requirement (withdraw only if K+ other deposits exist), random withdrawal timing suggestions. \
                                Should enforce: require(block.timestamp >= depositTime + MIN_DELAY), require(anonymitySetSize >= MIN_SET_SIZE), encourage users to wait random \
                                intervals.",
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
