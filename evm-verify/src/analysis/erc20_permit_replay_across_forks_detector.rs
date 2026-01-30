use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc20PermitReplayVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct Erc20PermitReplayAcrossForksDetector {
    bytecode: Vec<u8>,
}

impl Erc20PermitReplayAcrossForksDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<Erc20PermitReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_missing_chain_id_validation());
        vulnerabilities.extend(self.detect_domain_separator_not_cached());
        vulnerabilities.extend(self.detect_nonce_replay_across_chains());
        vulnerabilities
    }

    fn detect_missing_chain_id_validation(&self) -> Vec<Erc20PermitReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // KECCAK256 (EIP-712 domain separator)
                let start = if pc > 150 { pc - 150 } else { 0 };
                let has_chainid = self.bytecode[start..pc].iter().any(|&b| b == 0x46);
                if !has_chainid {
                    vulns.push(Erc20PermitReplayVulnerability {
                        pc, vulnerability_type: "MissingChainIdValidation".to_string(),
                        description: format!("EIP-712 domain separator at PC {} doesn't include CHAIN_ID, allowing permit replay across forks. Attack: user signs permit on mainnet with EIP-2612, chain forks (e.g., Ethereum/Ethereum Classic split), attacker replays signature on fork chain. Real vulnerability: domain separator = keccak256(DOMAIN_TYPEHASH, name, version, address), missing chainId field. Example: user approves 100 USDC on Ethereum mainnet, attacker captures signature, replays on Ethereum PoW fork (ETHW), drains user's ETHW-USDC. Missing: DOMAIN_SEPARATOR = keccak256(abi.encode(typeHash, name, version, block.chainid, address)). Fix: always include block.chainid in domain separator, implement EIP-2612 spec correctly with CHAIN_ID protection.", pc),
                        confidence: 0.88,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_domain_separator_not_cached(&self) -> Vec<Erc20PermitReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x46 { // CHAINID
                let window_end = (pc + 80).min(self.bytecode.len());
                let recalculates_domain = self.bytecode[pc..window_end].iter().any(|&b| b == 0x20);
                if recalculates_domain {
                    let checks_cached = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x54).count() >= 2;
                    if !checks_cached {
                        vulns.push(Erc20PermitReplayVulnerability {
                            pc, vulnerability_type: "DomainSeparatorNotCached".to_string(),
                            description: format!("Domain separator recalculated at PC {} on every permit without caching, vulnerable to fork replay. Attack: contract recalculates DOMAIN_SEPARATOR with current chainId on each call, after hard fork with chainId change, old signatures invalid, but attacker can replay on original chain. Real issue: Optimism Bedrock upgrade changed chainId from 10 to 420, contracts recalculating domain separator broke. Missing: cache DOMAIN_SEPARATOR at deployment, check if chainId changed, recalculate only if fork detected. Should implement: immutable CACHED_DOMAIN_SEPARATOR, CACHED_CHAIN_ID, function _domainSeparatorV4() returns cached if chainId matches, else recalculates. Fix: store domain separator as immutable or cached variable.", pc),
                            confidence: 0.82,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_nonce_replay_across_chains(&self) -> Vec<Erc20PermitReplayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (nonce increment)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_nonce_read = self.bytecode[start..pc].iter().any(|&b| b == 0x54);
                if has_nonce_read {
                    let has_chain_validation = self.bytecode[start..pc].iter().any(|&b| b == 0x46);
                    if !has_chain_validation {
                        vulns.push(Erc20PermitReplayVulnerability {
                            pc, vulnerability_type: "NonceReplayAcrossChains".to_string(),
                            description: format!("Nonce increment at PC {} doesn't validate chain, allowing cross-chain nonce confusion. Attack: user's nonce = 5 on mainnet, also 5 on fork, attacker gets signature for nonce=5 permit on mainnet, replays on fork where nonce also 5. Real scenario: multichain token deployed on Ethereum and Polygon with same address, user signs permit nonce=10 on Ethereum, attacker replays on Polygon if nonce also 10. Missing: nonces mapping should be chain-specific or include chainId in storage slot. Exploit: signature farming - collect permits on low-value chain, replay on high-value chain. Fix: include chainId in nonce storage: nonces[chainId][owner] or validate DOMAIN_SEPARATOR includes current chainId.", pc),
                            confidence: 0.79,
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
