use crate::bytecode::opcodes::*;

pub struct CrossChainOracleLatencyArbitrageDetector {
    bytecode: Vec<u8>,
}

impl CrossChainOracleLatencyArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_cross_chain_oracle()
            && self.has_latency_exploitation()
    }

    fn has_cross_chain_oracle(&self) -> bool {
        // Multiple oracle calls suggesting cross-chain
        let oracle_count = self.bytecode.iter()
            .filter(|&&op| op == STATICCALL)
            .count();
        
        oracle_count >= 2
    }

    fn has_latency_exploitation(&self) -> bool {
        // Price arbitrage between chains
        self.has_price_comparison() && self.has_arbitrage_execution()
    }

    fn has_price_comparison(&self) -> bool {
        // Multiple STATICCALL followed by comparison
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == STATICCALL {
                // Look for another oracle call
                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.bytecode[j] == STATICCALL {
                        // Followed by comparison
                        for k in j+1..j.min(self.bytecode.len()).min(j+8) {
                            if matches!(self.bytecode[k], SUB | LT | GT) {
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

    fn has_arbitrage_execution(&self) -> bool {
        // Trade execution after price check
        self.has_swap_after_oracle()
    }

    fn has_swap_after_oracle(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == STATICCALL {
                // Look for swap after oracle
                for j in i+1..i.min(self.bytecode.len()).min(i+25) {
                    if self.is_swap_call(j) {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn is_swap_call(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.is_swap_selector(&self.bytecode[pos+1..])
    }

    fn is_swap_selector(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 2 { return false; }
        bytes[0] == 0x02 || bytes[0] == 0x12 || bytes[0] == 0x38
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_arbitrage() {
        let bytecode = vec![
            STATICCALL,                         // Chain A oracle
            STATICCALL,                         // Chain B oracle
            SUB,                                // Compare prices
            PUSH4, 0x02, 0x2c, 0x0d, 0x9f,     // swap (arbitrage)
            CALL,
        ];
        let detector = CrossChainOracleLatencyArbitrageDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_normal_oracle() {
        let bytecode = vec![
            STATICCALL,
            SSTORE,
        ];
        let detector = CrossChainOracleLatencyArbitrageDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
