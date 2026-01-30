use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum L2GasEstimationVulnerability {
    EstimateGasDoSVector { description: String, location: usize, confidence: f32 },
    L1DataFeeNotIncluded { description: String, location: usize, confidence: f32 },
}

pub struct L2GasEstimationVsActualGapDetector {
    bytecode: Vec<u8>,
}

impl L2GasEstimationVsActualGapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<L2GasEstimationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // L2 estimateGas() ≠ actual execution gas → DoS attacks
        for i in 0..self.bytecode.len().saturating_sub(80) {
            let section = &self.bytecode[i..std::cmp::min(i + 80, self.bytecode.len())];
            
            // Pattern: Complex loop or recursive calls (estimation struggles)
            let has_complex_loop = section.windows(15).any(|w| {
                w.contains(&0x56) && // JUMP (loop)
                w.contains(&0x57) && // JUMPI
                w.contains(&0xF1)    // CALL (in loop)
            });
            
            if has_complex_loop {
                vulnerabilities.push(L2GasEstimationVulnerability::EstimateGasDoSVector {
                    description: format!("L2 gas estimation gap at PC {}. Arbitrum/Optimism/Base: estimateGas() runs simulation with different state than actual execution. Attack: Function succeeds in estimation but reverts in execution. Example: Loop iterations = f(block.number). Estimation at block N estimates 10 iterations. Execution at block N+1 has 1000 iterations → out of gas. Relayers using estimateGas × 1.5 multiplier still fail. Use fixed gas limits for critical functions on L2.", i),
                    location: i,
                    confidence: 0.83,
                });
            }
            
            // L2-specific: L1 data fee not in estimation
            let has_large_calldata = section.iter().filter(|&&b| b == 0x35).count() > 5; // Multiple CALLDATALOAD
            if has_large_calldata {
                vulnerabilities.push(L2GasEstimationVulnerability::L1DataFeeNotIncluded {
                    description: format!("L2 L1 data fee estimation gap at PC {}. Optimism/Base: Total gas = L2 execution + L1 data fee. estimateGas() only returns L2 gas. Large calldata → high L1 fee (not estimated) → transaction fails. Example: 10KB calldata = 160K L1 gas @ 50 gwei = 0.008 ETH extra. Users underpay → reverts. Solution: Add buffer for L1 data fee or use eth_estimateGas with state overrides.", i),
                    location: i,
                    confidence: 0.79,
                });
            }
        }
        
        vulnerabilities
    }
}
