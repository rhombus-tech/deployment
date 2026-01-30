use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardForkChainSplitVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct HardForkChainSplitTokenDuplicationDetector {
    bytecode: Vec<u8>,
}

impl HardForkChainSplitTokenDuplicationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HardForkChainSplitVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_missing_chain_id_validation());
        vulnerabilities.extend(self.detect_replay_attack_vulnerability());
        vulnerabilities.extend(self.detect_fork_contingency_absence());
        vulnerabilities
    }

    fn detect_missing_chain_id_validation(&self) -> Vec<HardForkChainSplitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (state update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_transfer_logic = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 2;
                if has_transfer_logic {
                    let checks_chainid = self.bytecode[start..pc].iter().any(|&b| b == 0x46);
                    if !checks_chainid {
                        vulns.push(HardForkChainSplitVulnerability {
                            pc, vulnerability_type: "MissingChainIdValidation".to_string(),
                            description: format!("Token transfer at PC {} doesn't validate chain ID, vulnerable to replay attacks after hard fork. Attack: Ethereum hard forks creating two chains, user owns tokens on chain A, transfers tokens on chain A, transaction replayed on chain B, user loses tokens on both chains unintentionally. Real scenario: Ethereum/ETC split, user transfers 1000 tokens on Ethereum mainnet, attacker replays exact transaction on ETC chain, user's 1000 ETC tokens also transferred, double loss. Example: after contentious fork, user sells NFT for 100 ETH on chain A, buyer replays purchase transaction on chain B, user loses NFT on both chains but paid once. Missing: EIP-155 chain ID in transactions, domain separator with chainid. Should implement: require(block.chainid == INITIAL_CHAIN_ID), or include chainid in signed message. Fix: use EIP-712 domain separator including chainId, reject transactions if block.chainid != expectedChainId, implement chain split detection and pausability.", pc),
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

    fn detect_replay_attack_vulnerability(&self) -> Vec<HardForkChainSplitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (signature hash)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_signature_components = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 3;
                if has_signature_components {
                    let includes_chainid = self.bytecode[start..pc].iter().any(|&b| b == 0x46);
                    if !includes_chainid {
                        vulns.push(HardForkChainSplitVulnerability {
                            pc, vulnerability_type: "ReplayAttackVulnerability".to_string(),
                            description: format!("Signature verification at PC {} doesn't include chain ID, enabling cross-chain replay attacks. Attack: user signs message on chain A, attacker replays signature on chain B (post-fork), identical contract addresses and state, signature valid on both chains, attacker drains funds on both. Real attack: user approves token spending on Ethereum, hard fork occurs, attacker replays approval on forked chain, uses approval to transferFrom on both chains. Example: DAO vote signature for 'transfer 1M tokens to treasury', valid on mainnet, fork happens, attacker replays vote on fork chain, 1M tokens transferred on both chains to same treasury address. Missing: EIP-712 domain separator with chainId. Should implement: domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, chainId, address(this))). Fix: include block.chainid in all signature hashes, validate chainId matches expected value before signature verification, update domain separator on fork detection.", pc),
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

    fn detect_fork_contingency_absence(&self) -> Vec<HardForkChainSplitVulnerability> {
        let mut vulns = Vec::new();
        let mut has_chainid_check = false;
        let mut has_pause_mechanism = false;
        let mut pc = 0;
        
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x46 { // CHAINID
                has_chainid_check = true;
            }
            if opcode == 0x54 {
                let window = (pc + 20).min(self.bytecode.len());
                if self.bytecode[pc..window].iter().any(|&b| b == 0x15) {
                    has_pause_mechanism = true;
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        
        if !has_chainid_check || !has_pause_mechanism {
            vulns.push(HardForkChainSplitVulnerability {
                pc: 0, vulnerability_type: "ForkContingencyAbsence".to_string(),
                description: format!("Contract lacks fork contingency plan, no mechanism to handle chain splits. Attack: hard fork creates two chains, contract operates on both, token balances duplicated, governance state duplicated, attacker exploits differences between chains to drain funds. Real scenario: lending protocol with 1M DAI collateral, fork occurs, attacker borrows max on chain A, withdraws max on chain B, collateral insufficient on either chain to cover both loans. Example: AMM with 10M liquidity, fork creates two identical AMMs, arbitrage bots exploit price differences between fork chains, original chain drained. Missing: fork detection, chain ID validation, emergency pause on fork. Should implement: constructor stores INITIAL_CHAIN_ID, checks block.chainid == INITIAL_CHAIN_ID on sensitive operations, pauses if mismatch. Fix: add require(block.chainid == EXPECTED_CHAIN_ID) to critical functions, implement automatic pause on chain ID change, provide governance mechanism to update expected chain ID post-fork."),
                confidence: 0.79,
            });
        }
        
        vulns
    }
}
