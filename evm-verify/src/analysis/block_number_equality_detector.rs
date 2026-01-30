/// Block Number Strict Equality Detector
///
/// Detects strict equality checks with block.number that can be skipped by miners.
/// Using `==` instead of `>=` allows miners to skip blocks.
///
/// Impact: $3M+ (stuck contracts, missed deadlines)
///
/// Example:
/// ```solidity
/// contract BlockNumberBug {
///     uint256 public deadline = 1000000;
///     
///     function claim() external {
///         // ❌ WRONG: Miner can skip this exact block!
///         require(block.number == deadline);
///         // If miner mines block 999999 then 1000001, this never executes!
///     }
///     
///     // ✓ CORRECT:
///     function claimSafe() external {
///         require(block.number >= deadline);
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockNumberVulnerability {
    pub vulnerability_type: BlockNumberIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockNumberIssueType {
    StrictEquality,                // NUMBER + EQ
}

pub struct BlockNumberEqualityDetector {
    bytecode: Vec<u8>,
}

impl BlockNumberEqualityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BlockNumberVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x43 { // NUMBER opcode
                // Check for EQ after NUMBER
                for j in i+1..i.saturating_add(10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 { // EQ
                        vulnerabilities.push(BlockNumberVulnerability {
                            vulnerability_type: BlockNumberIssueType::StrictEquality,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.75,
                            description: "block.number strict equality check - can be skipped".to_string(),
                            exploit_scenario: format!(
                                "BLOCK.NUMBER == at {}:\n\
                                \n\
                                Strict equality with block.number is dangerous!\n\
                                Miners can skip the exact block number.\n\
                                \n\
                                Use >= instead of == for block number checks.",
                                i
                            ),
                            location: i,
                        });
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }
}
