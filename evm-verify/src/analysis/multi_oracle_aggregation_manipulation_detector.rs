use crate::bytecode::opcodes::*;

pub struct MultiOracleAggregationManipulationDetector {
    bytecode: Vec<u8>,
}

impl MultiOracleAggregationManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_multiple_oracles()
            && (self.has_weak_aggregation() || self.has_manipulation_vulnerability())
    }

    fn has_multiple_oracles(&self) -> bool {
        // Multiple STATICCALL operations
        let oracle_count = self.bytecode.iter()
            .filter(|&&op| op == STATICCALL)
            .count();
        
        oracle_count >= 2
    }

    fn has_weak_aggregation(&self) -> bool {
        // Simple average without outlier detection
        self.has_simple_average() && !self.has_outlier_detection()
    }

    fn has_simple_average(&self) -> bool {
        // ADD followed by DIV (averaging)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == ADD {
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

    fn has_outlier_detection(&self) -> bool {
        // Multiple comparisons suggesting outlier filtering
        let comparison_count = self.bytecode.iter()
            .filter(|&&op| matches!(op, LT | GT))
            .count();
        
        comparison_count >= 3
    }

    fn has_manipulation_vulnerability(&self) -> bool {
        // Single oracle can dominate result
        self.has_weighted_average() && !self.has_weight_limits()
    }

    fn has_weighted_average(&self) -> bool {
        // MUL before ADD (weighted calculation)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == MUL {
                for j in i+1..i.min(self.bytecode.len()).min(i+4) {
                    if self.bytecode[j] == ADD {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_weight_limits(&self) -> bool {
        // Weight validation (LT/GT checks on weights)
        let mut has_mul = false;
        let mut has_check = false;

        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if opcode == MUL {
                has_mul = true;
            }
            if has_mul && matches!(opcode, LT | GT) {
                has_check = true;
            }
        }

        has_mul && has_check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregation_manipulation() {
        let bytecode = vec![
            STATICCALL,             // Oracle 1
            STATICCALL,             // Oracle 2
            ADD, DIV,               // Simple average (no outlier detection)
        ];
        let detector = MultiOracleAggregationManipulationDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_protected_aggregation() {
        let bytecode = vec![
            STATICCALL,             // Oracle 1
            STATICCALL,             // Oracle 2
            LT, LT, GT,             // Outlier detection
            ADD, DIV,
        ];
        let detector = MultiOracleAggregationManipulationDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
