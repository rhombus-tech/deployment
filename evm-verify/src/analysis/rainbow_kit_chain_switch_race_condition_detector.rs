use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RainbowKitVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct RainbowKitChainSwitchRaceConditionDetector {
    bytecode: Vec<u8>,
}

impl RainbowKitChainSwitchRaceConditionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RainbowKitVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_chain_id_race_condition());
        vulnerabilities.extend(self.detect_stale_chain_state());
        vulnerabilities.extend(self.detect_cross_chain_signature_replay());

        vulnerabilities
    }

    fn detect_chain_id_race_condition(&self) -> Vec<RainbowKitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x46 { // CHAINID
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_transaction_execution = window.iter().any(|&b| b == 0xF1); // CALL
                
                if has_transaction_execution {
                    let validates_chain_consistency = window.iter().filter(|&&b| b == 0x14).count() >= 2; // EQ checks
                    let has_atomic_verification = window.iter().any(|&b| b == 0xFD); // REVERT on mismatch
                    
                    if !validates_chain_consistency {
                        vulns.push(RainbowKitVulnerability {
                            pc,
                            vulnerability_type: "ChainIdRaceCondition".to_string(),
                            description: format!(
                                "Chain ID check at PC {} vulnerable to race condition during chain switch. Attack: user initiates transaction on Ethereum mainnet, mid-signing wallet \
                                switches to Polygon, transaction signed with wrong chain ID, replay on unintended chain. Race condition flow: (1) dApp reads chainId = 1 (Ethereum), (2) \
                                prepares transaction for Ethereum contract, (3) prompts user signature, (4) user clicks 'Switch to Polygon' in wallet during signing, (5) chainId now = 137, \
                                (6) transaction signed on Polygon instead of Ethereum, (7) if contract at same address on both chains, executes on wrong network. Example: user selling NFT on \
                                OpenSea (Ethereum), switches to Polygon network accidentally while signing, NFT transfer executes on Polygon (where they don't own NFT), transaction fails \
                                but paid gas. Or worse: DEX swap prepared for Ethereum, signed on BSC, different price/liquidity causes loss. Missing: chain ID validation in transaction \
                                itself, atomic chain verification, UI freeze during signing. Should implement: include chainId in EIP-712 domain separator, verify chainId before sending \
                                transaction, lock UI during signing to prevent chain switch, re-check chainId matches before broadcast.",
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

    fn detect_stale_chain_state(&self) -> Vec<RainbowKitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (chain state)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let uses_cached_chain_data = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if uses_cached_chain_data {
                    let revalidates_on_use = window.iter().any(|&b| b == 0x46); // CHAINID recheck
                    let has_staleness_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !revalidates_on_use {
                        vulns.push(RainbowKitVulnerability {
                            pc,
                            vulnerability_type: "StaleChainState".to_string(),
                            description: format!(
                                "Chain state caching at PC {} doesn't revalidate after network changes. Attack: dApp caches chain-specific data (contract addresses, balances), user \
                                switches chains, dApp uses stale data from old chain. Stale state issues: (1) dApp caches USDC contract address for Ethereum, user switches to Polygon, \
                                dApp tries to interact with Ethereum USDC address on Polygon (different contract or nonexistent), (2) cached user balance from old chain shown, user thinks \
                                they have funds they don't, (3) cached allowances from different chain cause approval confusion. Example: user on Ethereum with 1000 USDC approved to Uniswap, \
                                switches to Arbitrum (where they have 0 USDC), dApp shows 'Approved: 1000 USDC' from cache, user tries to swap, transaction fails. Or: dApp caches nonce from \
                                Ethereum, user switches to Optimism, sends transaction with wrong nonce, transaction rejected. Missing: chain change event listeners, cache invalidation, \
                                state refresh. Should implement: listen to chainChanged event, clear all cached chain-specific state on network switch, re-query balances/allowances/nonces, \
                                add cache TTL, include chainId in cache keys.",
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

    fn detect_cross_chain_signature_replay(&self) -> Vec<RainbowKitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (signature message hash)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_signature_data = window.iter().filter(|&&b| b == 0x35).count() >= 2;
                
                if has_signature_data {
                    let includes_chain_id = window.iter().any(|&b| b == 0x46); // CHAINID
                    let prevents_replay = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    
                    if !includes_chain_id {
                        vulns.push(RainbowKitVulnerability {
                            pc,
                            vulnerability_type: "CrossChainSignatureReplay".to_string(),
                            description: format!(
                                "Signature generation at PC {} omits chain ID allowing cross-chain replay. Attack: user signs message on one chain, attacker replays signature on different \
                                chain if contracts at same address. Cross-chain replay: (1) user signs EIP-712 Permit on Ethereum for USDC approval, (2) attacker captures signature, (3) \
                                replays signature on Polygon (USDC at same address), (4) if domain separator doesn't include chainId, signature valid on Polygon, (5) attacker drains user's \
                                Polygon USDC. Example: multi-chain NFT project deployed at CREATE2 addresses (same on all chains), user signs mint signature on Ethereum, attacker replays on \
                                BSC/Polygon/Arbitrum, mints NFTs on all chains without paying. Or: signed message voting on governance, replay on other chains to manipulate cross-chain \
                                governance. Real risk: CREATE2 makes cross-chain contract addresses deterministic, increases replay attack surface. Missing: chainId in signature domain, \
                                per-chain nonces, cross-chain signature tracking. Should enforce: always include chainId in EIP-712 domain separator, verify chainId matches current chain \
                                before signature verification, use separate nonces per chain, warn users signing on multiple chains for same contract.",
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
