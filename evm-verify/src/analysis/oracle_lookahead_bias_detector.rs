use crate::bytecode::opcodes::*;

pub struct OracleLookaheadBiasDetector {
    bytecode: Vec<u8>,
}

impl OracleLookaheadBiasDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_oracle_usage()
            && self.has_lookahead_vulnerability()
    }

    fn has_oracle_usage(&self) -> bool {
        // External call to oracle (STATICCALL for price feeds)
        self.bytecode.iter().any(|&op| op == STATICCALL || op == CALL)
    }

    fn has_lookahead_vulnerability(&self) -> bool {
        // Using future block data or predictable sources
        self.has_future_block_access() || self.has_predictable_price_source()
    }

    fn has_future_block_access(&self) -> bool {
        // BLOCKNUMBER or TIMESTAMP used with oracle
        let mut has_time_source = false;
        let mut has_oracle_call = false;

        for &opcode in &self.bytecode {
            if opcode == TIMESTAMP || opcode == BLOCKNUMBER {
                has_time_source = true;
            }
            if (opcode == STATICCALL || opcode == CALL) && has_time_source {
                has_oracle_call = true;
            }
        }

        has_time_source && has_oracle_call
    }

    fn has_predictable_price_source(&self) -> bool {
        // Single oracle call without staleness check
        self.has_single_oracle_call() && !self.has_staleness_check()
    }

    fn has_single_oracle_call(&self) -> bool {
        let oracle_calls = self.bytecode.iter()
            .filter(|&&op| op == STATICCALL)
            .count();
        
        oracle_calls == 1
    }

    fn has_staleness_check(&self) -> bool {
        // TIMESTAMP comparison after oracle call
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == STATICCALL {
                // Check for timestamp comparison after
                for j in i+1..i.min(self.bytecode.len()).min(i+12) {
                    if self.bytecode[j] == TIMESTAMP {
                        for k in j+1..j.min(self.bytecode.len()).min(j+5) {
                            if matches!(self.bytecode[k], LT | GT | SUB) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookahead_bias() {
        let bytecode = vec![
            TIMESTAMP,              // Use timestamp
            STATICCALL,             // Single oracle call (no staleness check)
        ];
        let detector = OracleLookaheadBiasDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_protected_oracle() {
        let bytecode = vec![
            STATICCALL,             // Oracle call
            TIMESTAMP, SUB,         // Staleness check
            LT,
        ];
        let detector = OracleLookaheadBiasDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
