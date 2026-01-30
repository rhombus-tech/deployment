use crate::bytecode::opcodes::*;

pub struct LiquidityFragmentationAttackDetector {
    bytecode: Vec<u8>,
}

impl LiquidityFragmentationAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_liquidity_splitting_pattern()
            && self.has_multiple_pool_interactions()
            && self.has_price_impact_exploitation()
    }

    fn has_liquidity_splitting_pattern(&self) -> bool {
        // Multiple small transfers instead of one large one
        self.count_transfer_operations() >= 5
    }

    fn count_transfer_operations(&self) -> usize {
        let mut count = 0;
        let mut i = 0;

        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                // transfer: 0xa9059cbb, transferFrom: 0x23b872dd
                if (self.bytecode[i+1] == 0xa9 && self.bytecode[i+2] == 0x05)
                    || (self.bytecode[i+1] == 0x23 && self.bytecode[i+2] == 0xb8) {
                    count += 1;
                }
            }
            i += 1;
        }
        count
    }

    fn has_multiple_pool_interactions(&self) -> bool {
        // Calls to different pool addresses
        let call_count = self.bytecode.iter()
            .filter(|&&op| op == CALL)
            .count();
        
        call_count >= 3
    }

    fn has_price_impact_exploitation(&self) -> bool {
        // Small trades to minimize price impact per trade
        self.has_amount_division() && self.has_loop_pattern()
    }

    fn has_amount_division(&self) -> bool {
        // Dividing amounts into smaller chunks
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == DIV || self.bytecode[i] == SDIV {
                // Followed by loop or multiple transfers
                for j in i+1..i.min(self.bytecode.len()).min(i+8) {
                    if self.bytecode[j] == JUMPI || self.is_transfer_selector(j) {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_loop_pattern(&self) -> bool {
        // Loop with CALL inside
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == JUMPDEST {
                let mut has_call = false;
                let mut has_jump_back = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.bytecode[j] == CALL {
                        has_call = true;
                    }
                    if self.bytecode[j] == JUMPI {
                        has_jump_back = true;
                    }
                }

                if has_call && has_jump_back {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn is_transfer_selector(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && ((self.bytecode[pos+1] == 0xa9 && self.bytecode[pos+2] == 0x05)
                || (self.bytecode[pos+1] == 0x23 && self.bytecode[pos+2] == 0xb8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liquidity_fragmentation() {
        let bytecode = vec![
            DIV,                                // Divide amount
            JUMPDEST,                           // Loop start
            PUSH4, 0xa9, 0x05, 0x9c, 0xbb,     // transfer
            CALL,                               // Pool 1
            PUSH4, 0xa9, 0x05, 0x9c, 0xbb,     // transfer
            CALL,                               // Pool 2
            PUSH4, 0xa9, 0x05, 0x9c, 0xbb,     // transfer
            CALL,                               // Pool 3
            JUMPI,                              // Loop back
        ];
        let detector = LiquidityFragmentationAttackDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_normal_swap() {
        let bytecode = vec![
            PUSH4, 0xa9, 0x05, 0x9c, 0xbb,
            CALL,
        ];
        let detector = LiquidityFragmentationAttackDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
