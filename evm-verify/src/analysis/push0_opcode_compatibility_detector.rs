use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Push0CompatibilityVulnerability {
    Push0OnPreShanghaiChain { description: String, location: usize, confidence: f32 },
    SolidityVersionMismatch { description: String, location: usize, confidence: f32 },
    MissingEvmVersionPragma { description: String, location: usize, confidence: f32 },
}

pub struct Push0OpcodeCompatibilityDetector {
    bytecode: Vec<u8>,
}

impl Push0OpcodeCompatibilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Push0CompatibilityVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_push0_usage());
        vulnerabilities
    }
    
    fn detect_push0_usage(&self) -> Vec<Push0CompatibilityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // PUSH0 opcode is 0x5F (introduced in Shanghai)
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x5F {
                // Check context: PUSH0 followed by typical stack operations
                let has_push0_pattern = if i + 3 < self.bytecode.len() {
                    let next_ops = &self.bytecode[i+1..i+3];
                    // Common patterns: PUSH0 DUP1, PUSH0 SWAP1, PUSH0 MSTORE
                    next_ops.contains(&0x80) || next_ops.contains(&0x90) || next_ops.contains(&0x52)
                } else {
                    false
                };
                
                if has_push0_pattern {
                    vulnerabilities.push(Push0CompatibilityVulnerability::Push0OnPreShanghaiChain {
                        description: format!("PUSH0 opcode (0x5F) detected at PC {}. Solidity 0.8.20+ uses PUSH0 by default. CRITICAL: Contract will fail on pre-Shanghai chains (Arbitrum One, Polygon PoS, BSC, Avalanche C-Chain before upgrades). Set `evm-version` to 'paris' or lower in compiler settings.", i),
                        location: i,
                        confidence: 0.95,
                    });
                }
            }
        }
        
        // Check for multiple PUSH0 usage (strong indicator of Solidity 0.8.20+)
        let push0_count = self.bytecode.iter().filter(|&&b| b == 0x5F).count();
        if push0_count > 5 {
            vulnerabilities.push(Push0CompatibilityVulnerability::SolidityVersionMismatch {
                description: format!("Contract contains {} PUSH0 opcodes. Compiled with Solidity 0.8.20+ for Shanghai+ EVM. Deployment will FAIL on: Arbitrum One (pre-ArbOS 11), Polygon PoS (pre-Napoli), BSC, Avalanche C-Chain (pre-Durango), Fantom Opera, Optimism (pre-Ecotone). Solution: Compile with --evm-version paris", push0_count),
                location: 0,
                confidence: 0.98,
            });
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push0_detection() {
        // Bytecode with PUSH0 followed by DUP1
        let bytecode = vec![
            0x60, 0x80, // PUSH1 0x80
            0x5F,       // PUSH0 (Shanghai+)
            0x80,       // DUP1
            0x52,       // MSTORE
        ];
        
        let detector = Push0OpcodeCompatibilityDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| matches!(v, Push0CompatibilityVulnerability::Push0OnPreShanghaiChain { .. })));
    }

    #[test]
    fn test_multiple_push0() {
        // Bytecode with many PUSH0 opcodes
        let mut bytecode = vec![0x60, 0x80]; // PUSH1 0x80
        for _ in 0..10 {
            bytecode.push(0x5F); // PUSH0
            bytecode.push(0x80); // DUP1
        }
        
        let detector = Push0OpcodeCompatibilityDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.len() >= 2); // Both individual and version mismatch
    }
}
