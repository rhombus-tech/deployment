use crate::bytecode::opcodes::*;

pub struct ProtocolFeeAvoidanceDetector {
    bytecode: Vec<u8>,
}

impl ProtocolFeeAvoidanceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_fee_calculation()
            && (self.has_fee_bypass() || self.has_route_optimization())
    }

    fn has_fee_calculation(&self) -> bool {
        // Fee calculation using MUL and DIV
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == MUL {
                for j in i+1..i.min(self.bytecode.len()).min(i+4) {
                    if self.bytecode[j] == DIV {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_fee_bypass(&self) -> bool {
        // Direct transfers avoiding fee-taking functions
        self.has_direct_transfer_pattern() || self.has_zero_fee_route()
    }

    fn has_direct_transfer_pattern(&self) -> bool {
        // transfer() instead of swap() to avoid fees
        let transfer_count = self.count_transfers();
        let swap_count = self.count_swaps();
        
        transfer_count >= 2 && swap_count == 0
    }

    fn count_transfers(&self) -> usize {
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

    fn count_swaps(&self) -> usize {
        let mut count = 0;
        let mut i = 0;

        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+4];
                if self.is_swap_selector(selector) {
                    count += 1;
                }
            }
            i += 1;
        }
        count
    }

    fn is_swap_selector(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 2 { return false; }
        bytes[0] == 0x02 || bytes[0] == 0x12 || bytes[0] == 0x38
    }

    fn has_zero_fee_route(&self) -> bool {
        // Special routes or pool selection to minimize fees
        self.has_pool_selection() && self.has_conditional_routing()
    }

    fn has_pool_selection(&self) -> bool {
        // Multiple pool address loads (choosing best route)
        let sload_count = self.bytecode.iter()
            .filter(|&&op| op == SLOAD)
            .count();
        
        sload_count >= 3
    }

    fn has_conditional_routing(&self) -> bool {
        // Conditional jumps based on fee comparisons
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == MUL || self.bytecode[i] == DIV {
                // Fee calculation
                for j in i+1..i.min(self.bytecode.len()).min(i+10) {
                    // Comparison
                    if matches!(self.bytecode[j], LT | GT) {
                        // Followed by conditional jump
                        for k in j+1..j.min(self.bytecode.len()).min(j+5) {
                            if self.bytecode[k] == JUMPI {
                                return true;
                            }
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_route_optimization(&self) -> bool {
        // Multi-hop routing to split trades and reduce fees
        self.has_multi_hop_pattern() && self.has_amount_splitting()
    }

    fn has_multi_hop_pattern(&self) -> bool {
        // Multiple sequential calls
        let call_count = self.bytecode.iter()
            .filter(|&&op| op == CALL)
            .count();
        
        call_count >= 3
    }

    fn has_amount_splitting(&self) -> bool {
        // DIV operation to split amounts
        self.bytecode.iter().any(|&op| op == DIV)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_avoidance() {
        let bytecode = vec![
            MUL, DIV,                           // Fee calculation
            SLOAD, SLOAD, SLOAD,                // Load pool addresses
            LT,                                 // Compare fees
            JUMPI,                              // Route selection
            PUSH4, 0xa9, 0x05, 0x9c, 0xbb,     // Direct transfer
            CALL,
            PUSH4, 0xa9, 0x05, 0x9c, 0xbb,     // Another transfer
            CALL,
        ];
        let detector = ProtocolFeeAvoidanceDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_normal_swap() {
        let bytecode = vec![
            MUL, DIV,                           // Fee calculation
            PUSH4, 0x02, 0x2c, 0x0d, 0x9f,     // swap (pays fees)
            CALL,
        ];
        let detector = ProtocolFeeAvoidanceDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
