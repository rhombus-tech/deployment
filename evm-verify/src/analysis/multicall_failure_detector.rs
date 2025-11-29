/// Multicall Partial Failure Detector
/// Detects when multicall batches can fail partially, leaving inconsistent state

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticallFailureVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub pc: usize,
}

pub struct MulticallFailureDetector {
    bytecode: Vec<u8>,
}

impl MulticallFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MulticallFailureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // Pattern: Loop with CALL but no full revert on failure
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // JUMPDEST indicates loop start
            if opcode == 0x5B {
                if self.has_multicall_pattern_after(pc) {
                    vulns.push(MulticallFailureVulnerability {
                        severity: SecuritySeverity::High,
                        description: "Multicall loop allows partial failures - inconsistent state possible".to_string(),
                        exploit_scenario: "Multicall partial failure attack:\n\
                            1. User calls multicall([txA, txB, txC])\n\
                            2. txA succeeds (state changed)\n\
                            3. txB fails (attacker intentional revert)\n\
                            4. Contract continues processing\n\
                            5. txC succeeds (state changed)\n\
                            6. Result: Partial execution = broken invariants\n\
                            \n\
                            Example: Uniswap V3 multicall\n\
                            - Swap succeeds\n\
                            - Liquidity add fails\n\
                            - Result: Exposed to IL without protection".to_string(),
                        remediation: "Options:\n\
                            1. All-or-nothing (revert entire batch):\n\
                            for (uint i = 0; i < calls.length; i++) {\n\
                                (bool success, ) = calls[i].target.call(calls[i].data);\n\
                                require(success, 'Multicall failed');  // Revert all!\n\
                            }\n\
                            \n\
                            2. Return success flags + allow caller to decide:\n\
                            bool[] memory results = new bool[](calls.length);\n\
                            for (uint i = 0; i < calls.length; i++) {\n\
                                (results[i], ) = calls[i].target.call(calls[i].data);\n\
                            }\n\
                            return results;  // Let caller handle failures\n\
                            \n\
                            3. Use try/catch with explicit handling".to_string(),
                        pc,
                    });
                }
            }

            // Pattern: CALL without immediate ISZERO check
            if opcode == 0xF1 {  // CALL
                if !self.has_success_check_after(pc, 10) {
                    if self.is_in_loop_context(pc) {
                        vulns.push(MulticallFailureVulnerability {
                            severity: SecuritySeverity::Critical,
                            description: "CALL in loop without success check - silent failures".to_string(),
                            exploit_scenario: "Silent multicall failure:\n\
                                1. Loop calls multiple functions\n\
                                2. One call fails\n\
                                3. No success check = continues execution\n\
                                4. State partially updated\n\
                                5. User thinks all succeeded\n\
                                6. Funds lost or invariants broken".to_string(),
                            remediation: "Always check call success:\n\
                                (bool success, bytes memory data) = target.call(data);\n\
                                require(success, string(data));  // Revert with error".to_string(),
                            pc,
                        });
                    }
                }
            }

            pc += 1;
            if pc > 0 && self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }

        vulns
    }

    fn has_multicall_pattern_after(&self, jumpdest_pc: usize) -> bool {
        let end = (jumpdest_pc + 200).min(self.bytecode.len());
        
        // Look for: CALL + loop back (JUMP to JUMPDEST)
        let has_call = self.bytecode[jumpdest_pc..end].iter().any(|&b| b == 0xF1);
        let has_loop_back = self.bytecode[jumpdest_pc..end].iter().any(|&b| b == 0x56);
        
        has_call && has_loop_back
    }

    fn has_success_check_after(&self, call_pc: usize, window: usize) -> bool {
        let end = (call_pc + window).min(self.bytecode.len());
        
        // Look for ISZERO (checking success bool) followed by JUMPI
        self.bytecode[call_pc..end].windows(2).any(|w| 
            w[0] == 0x15 && w[1] == 0x57  // ISZERO + JUMPI
        )
    }

    fn is_in_loop_context(&self, pc: usize) -> bool {
        // Check if there's a JUMPDEST before and JUMP after (loop pattern)
        let start = pc.saturating_sub(100);
        let end = (pc + 100).min(self.bytecode.len());
        
        let has_jumpdest_before = self.bytecode[start..pc].iter().any(|&b| b == 0x5B);
        let has_jump_after = self.bytecode[pc..end].iter().any(|&b| b == 0x56 || b == 0x57);
        
        has_jumpdest_before && has_jump_after
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_unchecked_multicall() {
        let bytecode = vec![
            0x5B,        // JUMPDEST (loop)
            0xF1,        // CALL
            0x56,        // JUMP (loop back, no success check!)
        ];
        let detector = MulticallFailureDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect unchecked multicall");
    }
}
