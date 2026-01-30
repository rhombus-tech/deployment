use crate::bytecode::opcodes::*;

pub struct JitLiquidityBotDetectionEvasionDetector {
    bytecode: Vec<u8>,
}

impl JitLiquidityBotDetectionEvasionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_jit_liquidity_pattern() 
            && self.has_evasion_techniques()
            && self.has_single_block_behavior()
    }

    fn has_jit_liquidity_pattern(&self) -> bool {
        // JIT liquidity: add liquidity -> target tx -> remove liquidity
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(50) {
            // Look for liquidity provision pattern (CALL to addLiquidity)
            if self.bytecode[i] == CALL {
                // Check for immediate removal pattern within same block
                for j in i+1..i+40 {
                    if j < self.bytecode.len() && self.bytecode[j] == CALL {
                        // Check for BLOCKNUMBER checks (single block constraint)
                        if self.has_blocknumber_check_between(i, j) {
                            return true;
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_evasion_techniques(&self) -> bool {
        // Evasion: randomized timing, value obfuscation, call indirection
        self.has_timestamp_randomization() 
            || self.has_value_obfuscation()
            || self.has_call_indirection()
    }

    fn has_timestamp_randomization(&self) -> bool {
        // Look for TIMESTAMP followed by arithmetic that creates randomness
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == TIMESTAMP {
                // Check for MOD or AND operations to create pseudo-randomness
                for j in i+1..i.min(self.bytecode.len()).min(i+8) {
                    if self.bytecode[j] == MOD || self.bytecode[j] == AND {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_value_obfuscation(&self) -> bool {
        // Look for complex arithmetic before value transfers
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.is_push_opcode(self.bytecode[i]) {
                let mut arithmetic_ops = 0;
                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.is_arithmetic_op(self.bytecode[j]) {
                        arithmetic_ops += 1;
                    }
                    if self.bytecode[j] == CALL && arithmetic_ops >= 3 {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_call_indirection(&self) -> bool {
        // Look for DELEGATECALL or CALLCODE to obfuscate target
        self.bytecode.iter().any(|&op| op == DELEGATECALL || op == CALLCODE)
    }

    fn has_single_block_behavior(&self) -> bool {
        // Verify operations constrained to single block
        let blocknumber_count = self.bytecode.iter().filter(|&&op| op == BLOCKNUMBER).count();
        blocknumber_count >= 2 // Multiple block checks indicate single-block constraint
    }

    fn has_blocknumber_check_between(&self, start: usize, end: usize) -> bool {
        for i in start..end.min(self.bytecode.len()) {
            if self.bytecode[i] == BLOCKNUMBER {
                return true;
            }
        }
        false
    }

    fn is_push_opcode(&self, opcode: u8) -> bool {
        (PUSH1..=PUSH32).contains(&opcode)
    }

    fn is_arithmetic_op(&self, opcode: u8) -> bool {
        matches!(opcode, ADD | MUL | SUB | DIV | SDIV | MOD | SMOD | EXP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jit_liquidity_evasion_detection() {
        let bytecode = vec![
            PUSH1, 0x01,
            TIMESTAMP, MOD,  // Timestamp randomization
            CALL,            // Add liquidity
            BLOCKNUMBER,     // Block check
            PUSH1, 0x02,
            CALL,            // Remove liquidity
        ];
        let detector = JitLiquidityBotDetectionEvasionDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_no_jit_pattern() {
        let bytecode = vec![PUSH1, 0x01, ADD, SSTORE];
        let detector = JitLiquidityBotDetectionEvasionDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
