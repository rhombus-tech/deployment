use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompoundEdgeCaseVulnerability {
    MultipleEdgesSimultaneous { description: String, location: usize, confidence: f32 },
    EdgeCaseInteraction { description: String, location: usize, confidence: f32 },
}

pub struct CompoundEdgeCaseDetector {
    bytecode: Vec<u8>,
}

impl CompoundEdgeCaseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<CompoundEdgeCaseVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            let section = &self.bytecode[i..std::cmp::min(i + 80, self.bytecode.len())];
            
            // Pattern: Multiple max/min values in same operation
            let max_count = section.windows(2).filter(|w| w == &[0x60, 0xFF]).count(); // PUSH1 0xFF
            let has_math = section.contains(&0x02) || section.contains(&0x04); // MUL or DIV
            
            if max_count >= 2 && has_math {
                vulnerabilities.push(CompoundEdgeCaseVulnerability::MultipleEdgesSimultaneous {
                    description: format!("Compound edge case at PC {}. Multiple edge values (uint256.max, 0, etc.) in same operation. Attack: uint256.max * uint256.max, or uint256.max + 1, or divide by 0 with max numerator. Example: approve(uint256.max) then transferFrom(uint256.max) → double edge case. Single edge case tested, combination untested. Mitigation: Test all edge combinations, not just individual edges.", i),
                    location: i,
                    confidence: 0.79,
                });
            }
            
            // Pattern: Zero address with zero amount (both edges)
            let has_address = section.contains(&0x33) || section.contains(&0x35); // CALLER or CALLDATALOAD
            let has_zero_check = section.windows(5).filter(|w| w.contains(&0x15)).count(); // ISZERO
            
            if has_address && has_zero_check >= 2 {
                vulnerabilities.push(CompoundEdgeCaseVulnerability::EdgeCaseInteraction {
                    description: format!("Edge case interaction at PC {}. Multiple edge conditions interact. Example: transfer(address(0), 0) → both zero → unexpected path. Or: borrow(uint256.max) with collateral(0). Single edge case: safe. Combined: exploitable. Mitigation: Test Cartesian product of all edge cases, use fuzzing with multiple edges.", i),
                    location: i,
                    confidence: 0.74,
                });
            }
        }
        
        vulnerabilities
    }
}
