use crate::bytecode::opcodes::*;

pub struct OracleHeartbeatTimingAttackDetector {
    bytecode: Vec<u8>,
}

impl OracleHeartbeatTimingAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_oracle_dependency()
            && self.has_timing_vulnerability()
    }

    fn has_oracle_dependency(&self) -> bool {
        // Contract relies on oracle updates
        self.bytecode.iter().any(|&op| op == STATICCALL)
    }

    fn has_timing_vulnerability(&self) -> bool {
        // No heartbeat check or stale price acceptance
        !self.has_heartbeat_validation() || self.has_stale_price_acceptance()
    }

    fn has_heartbeat_validation(&self) -> bool {
        // TIMESTAMP check after oracle call
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == STATICCALL {
                // Check for timestamp validation
                let mut has_timestamp = false;
                let mut has_comparison = false;
                let mut has_revert = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.bytecode[j] == TIMESTAMP {
                        has_timestamp = true;
                    }
                    if has_timestamp && matches!(self.bytecode[j], SUB | LT | GT) {
                        has_comparison = true;
                    }
                    if has_comparison && self.bytecode[j] == REVERT {
                        has_revert = true;
                    }
                }

                if has_timestamp && has_comparison && has_revert {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_stale_price_acceptance(&self) -> bool {
        // Oracle call without freshness check
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == STATICCALL {
                // Check if result is used without timestamp validation
                let mut has_timestamp_check = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+12) {
                    if self.bytecode[j] == TIMESTAMP {
                        has_timestamp_check = true;
                    }
                }

                if !has_timestamp_check {
                    return true;
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
    fn test_heartbeat_attack() {
        let bytecode = vec![
            STATICCALL,             // Oracle call
            SSTORE,                 // Use price without freshness check
        ];
        let detector = OracleHeartbeatTimingAttackDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_protected_oracle() {
        let bytecode = vec![
            STATICCALL,             // Oracle call
            TIMESTAMP, SUB,         // Check update time
            LT,                     // Compare against heartbeat
            ISZERO, PUSH1, 0x08, JUMPI,
            REVERT,                 // Revert if stale
            JUMPDEST,
            SSTORE,
        ];
        let detector = OracleHeartbeatTimingAttackDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
