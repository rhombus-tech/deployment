use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkP2PVulnerability {
    EclipseAttackVector { description: String, location: usize, confidence: f32 },
    SybilAttackPattern { description: String, location: usize, confidence: f32 },
    RPCEndpointManipulation { description: String, location: usize, confidence: f32 },
}

pub struct NetworkP2PAttackDetector {
    bytecode: Vec<u8>,
}

impl NetworkP2PAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<NetworkP2PVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // P2P network attacks: Eclipse (isolate node), Sybil (fake identities), RPC manipulation
        
        for i in 0..self.bytecode.len().saturating_sub(95) {
            let section = &self.bytecode[i..std::cmp::min(i + 95, self.bytecode.len())];
            
            // Pattern 1: Single validator/node dependency
            let has_single_source = section.windows(12).any(|w| {
                w.contains(&0xFA) && // STATICCALL (single external call)
                !w.windows(8).any(|w2| w2.contains(&0xFA) && w2.contains(&0xFA)) // Not multiple calls
            });
            
            if has_single_source {
                vulnerabilities.push(NetworkP2PVulnerability::EclipseAttackVector {
                    description: format!("Eclipse attack vector at PC {}. Contract relies on single node/RPC endpoint. Attack: 1) Attacker controls user's RPC (malicious MetaMask RPC, compromised Infura), 2) Returns fake blockchain state, 3) User sees fake balances/data, 4) Signs malicious transaction. Or: Oracle contract calls single Chainlink node → attacker DDoS that node or compromises it → oracle returns fake price. Or: L2 with single sequencer → attacker isolates sequencer → censors transactions. Mitigation: Require data from N independent sources (N>=3), verify block hashes from multiple peers, use p2p consensus, fallback RPC endpoints.", i),
                    location: i,
                    confidence: 0.85,
                });
            }
            
            // Pattern 2: Identity verification without Sybil resistance
            let has_identity_check = section.windows(15).any(|w| {
                w.contains(&0x54) && // SLOAD (check if registered)
                w.contains(&0x14) && // EQ (compare address)
                w.contains(&0x57)    // JUMPI (allow/deny)
            });
            
            let no_stake_requirement = !section.windows(12).any(|w| {
                w.contains(&0x54) && // SLOAD (stake balance)
                w.contains(&0x10) && // LT (check minimum stake)
                w.contains(&0x57)    // JUMPI (enforce)
            });
            
            if has_identity_check && no_stake_requirement {
                vulnerabilities.push(NetworkP2PVulnerability::SybilAttackPattern {
                    description: format!("Sybil attack pattern at PC {}. System allows unlimited identities without cost → attacker creates many fake identities to manipulate. Examples: 1) DAO governance: Create 1000 addresses, vote 1000x → take over DAO. 2) Oracle network: Register 100 fake oracles → control majority → report fake prices. 3) Validator network: Spin up 1000 fake validators → 51% attack. 4) Reputation system: Create fake positive reviews. 5) Airdrop: Claim from 1000 addresses. Mitigation: Require stake per identity (economic cost), proof-of-humanity (Worldcoin), or quadratic voting (diminishing returns).", i),
                    location: i,
                    confidence: 0.87,
                });
            }
            
            // Pattern 3: Off-chain data source without verification
            let has_offchain_call = section.windows(10).any(|w| {
                w.contains(&0xFA) && // STATICCALL (external)
                w.contains(&0x3E)    // RETURNDATACOPY (use data)
            });
            
            let no_signature_check = !section.windows(15).any(|w| {
                w.contains(&0x20) && // SHA3 (hash data)
                w.contains(&0x01) && // ECRECOVER (check signature)
                w.contains(&0x14)    // EQ (verify signer)
            });
            
            if has_offchain_call && no_signature_check {
                vulnerabilities.push(NetworkP2PVulnerability::RPCEndpointManipulation {
                    description: format!("RPC endpoint manipulation at PC {}. Contract makes external call without verifying data authenticity. Attack: 1) User connects to malicious RPC (fake Infura/Alchemy clone), 2) Dapp queries contract state via RPC, 3) Malicious RPC returns fake data, 4) Dapp shows user has 1M ETH (fake), 5) User signs tx thinking they're rich. Or: Price oracle queries external API, attacker controls DNS → points to fake API → returns manipulated price. Real: $50M+ stolen via RPC manipulation 2022-2024. Fix: Sign all off-chain data (EIP-712), verify signatures on-chain, use multiple RPC endpoints and compare results, or use decentralized oracle networks.", i),
                    location: i,
                    confidence: 0.83,
                });
            }
        }
        
        vulnerabilities
    }
}
