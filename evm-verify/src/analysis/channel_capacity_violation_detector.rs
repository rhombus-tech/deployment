use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelCapacityVulnerability {
    EventLogOverflow { description: String, location: usize, confidence: f32 },
    CalldataExhaustion { description: String, location: usize, confidence: f32 },
    ReturnDataExplosion { description: String, location: usize, confidence: f32 },
}

pub struct ChannelCapacityViolationDetector {
    bytecode: Vec<u8>,
}

impl ChannelCapacityViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ChannelCapacityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Pattern 1: Unbounded event emission
            let has_log = section.windows(5).any(|w| {
                w.contains(&0xA0) || w.contains(&0xA1) || w.contains(&0xA2) || w.contains(&0xA3) || w.contains(&0xA4)
            });
            
            let has_loop = section.windows(10).any(|w| w.contains(&0x56) || w.contains(&0x57));
            
            if has_log && has_loop {
                vulnerabilities.push(ChannelCapacityVulnerability::EventLogOverflow {
                    description: format!("Channel capacity violation at PC {}. Unbounded event log emission. Attack: Emit massive events → exceed block gas limit → transaction fails. Shannon's theorem: Channel capacity C = B log₂(1 + S/N). Block gas limit = 30M → max ~5000 events/tx. Exceeding = information loss. Example: Loop emitting Transfer events → 10k iterations → exceeds gas → tx reverts. Or: DOS by forcing expensive event storage. Mitigation: Limit events per tx, batch emit, or paginate operations.", i),
                    location: i,
                    confidence: 0.85,
                });
            }
            
            // Pattern 2: Large calldata without bounds check
            let has_calldata_copy = section.contains(&0x37); // CALLDATACOPY
            let has_calldata_size = section.contains(&0x36); // CALLDATASIZE
            let no_size_check = !section.windows(10).any(|w| {
                w.contains(&0x36) && w.contains(&0x10) // CALLDATASIZE + LT (bound check)
            });
            
            if has_calldata_copy && has_calldata_size && no_size_check {
                vulnerabilities.push(ChannelCapacityVulnerability::CalldataExhaustion {
                    description: format!("Calldata exhaustion at PC {}. No bound on calldata size. Attack: Send massive calldata → exceeds capacity → DOS or high cost. Tx calldata limited to block gas limit / 16 gas per byte ≈ 1.875 MB per tx. Example: Function accepts bytes[] → attacker sends 2MB → tx consumes all block gas. Information capacity: limited by block. Mitigation: Check calldatasize < threshold, reject oversized inputs.", i),
                    location: i,
                    confidence: 0.79,
                });
            }
            
            // Pattern 3: Unbounded return data
            let has_return = section.contains(&0xF3); // RETURN
            let has_mstore_loop = has_loop && section.contains(&0x52); // MSTORE in loop
            
            if has_return && has_mstore_loop {
                vulnerabilities.push(ChannelCapacityVulnerability::ReturnDataExplosion {
                    description: format!("Return data explosion at PC {}. Unbounded data returned. Attack: Force function to return massive data → exceeds gas → revert or DOS. Return data limited by gas: each 32 bytes costs gas. Example: View function returns array[1M] → caller runs out of gas. Channel capacity exceeded. Mitigation: Paginate return data, limit array sizes, or return pointers not full data.", i),
                    location: i,
                    confidence: 0.77,
                });
            }
        }
        
        vulnerabilities
    }
}
