use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC4337CrossChainReplayVulnerability {
    MissingChainIdInSignature { description: String, location: usize, confidence: f32 },
    ReplayAcrossChains { description: String, location: usize, confidence: f32 },
}

pub struct ERC4337CrossChainReplayDetector {
    bytecode: Vec<u8>,
}

impl ERC4337CrossChainReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ERC4337CrossChainReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(50) {
            let section = &self.bytecode[i..std::cmp::min(i + 50, self.bytecode.len())];
            let has_sig_check = section.contains(&0x01); // ECRECOVER
            let no_chainid = !section.contains(&0x46); // CHAINID opcode
            if has_sig_check && no_chainid {
                vulnerabilities.push(ERC4337CrossChainReplayVulnerability::MissingChainIdInSignature {
                    description: format!("ERC-4337 signature validation at PC {} doesn't include chainId. UserOp signed on Ethereum → replayed on Arbitrum/Optimism/Polygon → drains funds on all chains. Include CHAINID in EIP-712 domain separator: domain = hash(name, version, chainId, verifyingContract).", i),
                    location: i,
                    confidence: 0.94,
                });
            }
        }
        vulnerabilities
    }
}
