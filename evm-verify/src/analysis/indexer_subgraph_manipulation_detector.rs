use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexerSubgraphVulnerability {
    EventLogSpoofing { description: String, location: usize, confidence: f32 },
    SubgraphDataPoisoning { description: String, location: usize, confidence: f32 },
    FrontendDataInjection { description: String, location: usize, confidence: f32 },
}

pub struct IndexerSubgraphManipulationDetector {
    bytecode: Vec<u8>,
}

impl IndexerSubgraphManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<IndexerSubgraphVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // The Graph / Dune Analytics: Off-chain indexers parse event logs
        // Attackers can emit fake events to poison subgraph data
        
        for i in 0..self.bytecode.len().saturating_sub(90) {
            let section = &self.bytecode[i..std::cmp::min(i + 90, self.bytecode.len())];
            
            // Pattern 1: Event emission without access control
            let has_event_emit = section.windows(10).any(|w| {
                w.contains(&0xA0) || // LOG0
                w.contains(&0xA1) || // LOG1
                w.contains(&0xA2) || // LOG2
                w.contains(&0xA3) || // LOG3
                w.contains(&0xA4)    // LOG4
            });
            
            let no_access_control = !section.windows(12).any(|w| {
                w.contains(&0x33) && // CALLER
                w.contains(&0x14) && // EQ (check authorized)
                w.contains(&0x57)    // JUMPI (enforce)
            });
            
            if has_event_emit && no_access_control {
                vulnerabilities.push(IndexerSubgraphVulnerability::EventLogSpoofing {
                    description: format!("Event log spoofing at PC {}. Events emitted without verification → attackers can poison subgraph. Real attack: Malicious contract emits fake Transfer(attacker, victim, 1000000 ETH) → The Graph indexes it → Dapp UI shows victim has 1M ETH → victim trusts fake data → signs malicious tx. Or: Fake Approval events → UI shows approved when not → user doesn't approve again → tx fails. Mitigation: 1) Verify msg.sender before LOG, 2) Frontend: verify events come from trusted contract addresses, 3) Subgraph: validate event data against contract state.", i),
                    location: i,
                    confidence: 0.89,
                });
            }
            
            // Pattern 2: Event data not validated against state
            let has_event_with_unchecked_data = section.windows(15).any(|w| {
                let has_log = w.contains(&0xA1) || w.contains(&0xA2) || w.contains(&0xA3);
                let has_mload = w.contains(&0x51); // MLOAD (event data from memory)
                let no_sload_verify = !w.contains(&0x54); // No SLOAD to verify
                has_log && has_mload && no_sload_verify
            });
            
            if has_event_with_unchecked_data {
                vulnerabilities.push(IndexerSubgraphVulnerability::SubgraphDataPoisoning {
                    description: format!("Subgraph data poisoning at PC {}. Event emits data not verified against storage → off-chain mismatch. Example: emit Transfer(from, to, amount) but actual storage: balances[to] unchanged → subgraph thinks transfer happened, on-chain state disagrees. Attack: 1) Emit fake events, 2) Subgraph indexes them, 3) Dapp queries subgraph → shows wrong data, 4) User makes decision based on fake data. Real impact: $10M+ via UI manipulation showing fake balances/approvals. Fix: Event data MUST match storage state, or emit events AFTER state changes, not before.", i),
                    location: i,
                    confidence: 0.84,
                });
            }
            
            // Pattern 3: Protocol relies on off-chain data without verification
            let has_external_data_read = section.windows(12).any(|w| {
                w.contains(&0xFA) && // STATICCALL (external read)
                w.contains(&0x3D) && // RETURNDATASIZE
                w.contains(&0x3E)    // RETURNDATACOPY
            });
            
            if has_external_data_read {
                let no_hash_verify = !section.windows(10).any(|w| {
                    w.contains(&0x20) && // SHA3 (verify data)
                    w.contains(&0x14)    // EQ (compare hash)
                });
                
                if no_hash_verify {
                    vulnerabilities.push(IndexerSubgraphVulnerability::FrontendDataInjection {
                        description: format!("Frontend data injection at PC {}. Contract accepts external data without cryptographic verification. Attack vectors: 1) Malicious RPC endpoint returns fake data → contract uses it. 2) MITM attack on API calls → inject fake oracle data. 3) Compromised The Graph node → returns poisoned subgraph data. 4) Frontend queries malicious indexer → shows fake prices/balances → user signs tx. Example: Contract queries 'getPrice()' from external source, no signature verification → attacker controls source → returns fake price → protocol liquidates wrong users. Fix: Require signed data (EIP-712), verify signatures on-chain, or use decentralized oracle network with consensus.", i),
                        location: i,
                        confidence: 0.82,
                    });
                }
            }
        }
        
        vulnerabilities
    }
}
