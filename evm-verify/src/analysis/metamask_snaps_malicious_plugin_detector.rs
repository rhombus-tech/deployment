use crate::bytecode::opcodes::*;

pub struct MetamaskSnapsMaliciousPluginDetector {
    bytecode: Vec<u8>,
}

impl MetamaskSnapsMaliciousPluginDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_snap_interaction_pattern()
            && (self.has_malicious_permission_abuse() || self.has_data_exfiltration())
    }

    fn has_snap_interaction_pattern(&self) -> bool {
        // Snaps interact with contracts via specific patterns
        self.has_signature_request_pattern() || self.has_transaction_insight_hooks()
    }

    fn has_signature_request_pattern(&self) -> bool {
        // Multiple signature requests (phishing)
        let ecrecover_count = self.count_ecrecover_calls();
        ecrecover_count >= 3
    }

    fn count_ecrecover_calls(&self) -> usize {
        let mut count = 0;
        let mut i = 0;

        while i < self.bytecode.len().saturating_sub(10) {
            // ECRECOVER precompile (address 0x01)
            if self.bytecode[i] == PUSH1 && i + 1 < self.bytecode.len() {
                if self.bytecode[i+1] == 0x01 {
                    for j in i+2..i.min(self.bytecode.len()).min(i+8) {
                        if self.bytecode[j] == STATICCALL || self.bytecode[j] == CALL {
                            count += 1;
                            break;
                        }
                    }
                }
            }
            i += 1;
        }
        count
    }

    fn has_transaction_insight_hooks(&self) -> bool {
        // Snap hooks into transaction flow
        self.has_calldata_inspection() && self.has_modification_capability()
    }

    fn has_calldata_inspection(&self) -> bool {
        // Multiple CALLDATALOAD operations
        self.bytecode.iter().filter(|&&op| op == CALLDATALOAD).count() >= 3
    }

    fn has_modification_capability(&self) -> bool {
        // Can modify calldata or state
        self.has_calldata_manipulation() || self.has_state_changes()
    }

    fn has_calldata_manipulation(&self) -> bool {
        // CALLDATALOAD followed by arithmetic then MSTORE (modifying data)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == CALLDATALOAD {
                let mut has_arithmetic = false;
                let mut has_mstore = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+12) {
                    if matches!(self.bytecode[j], ADD | SUB | MUL | DIV) {
                        has_arithmetic = true;
                    }
                    if self.bytecode[j] == MSTORE || self.bytecode[j] == MSTORE8 {
                        has_mstore = true;
                    }
                }

                if has_arithmetic && has_mstore {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_state_changes(&self) -> bool {
        // SSTORE operations indicating state modification
        self.bytecode.iter().any(|&op| op == SSTORE)
    }

    fn has_malicious_permission_abuse(&self) -> bool {
        // Unlimited approvals or excessive permissions
        self.has_unlimited_approval_requests()
            || self.has_private_key_extraction_pattern()
    }

    fn has_unlimited_approval_requests(&self) -> bool {
        // Multiple approve calls with max values
        let mut approve_count = 0;
        let mut i = 0;

        while i < self.bytecode.len().saturating_sub(40) {
            // approve selector 0x095ea7b3
            if self.is_approve_selector(i) {
                // Check for max uint256 value nearby
                if self.has_max_value_near(i, 30) {
                    approve_count += 1;
                }
            }
            i += 1;
        }

        approve_count >= 2
    }

    fn is_approve_selector(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.bytecode[pos+1] == 0x09
            && self.bytecode[pos+2] == 0x5e
    }

    fn has_max_value_near(&self, pos: usize, range: usize) -> bool {
        for i in pos..pos.min(self.bytecode.len()).min(pos + range) {
            if self.bytecode[i] == PUSH32 {
                if i + 32 < self.bytecode.len() {
                    let all_ff = (i+1..i+33).all(|j| self.bytecode.get(j) == Some(&0xFF));
                    if all_ff {
                        return true;
                    }
                }
            }
            // NOT(0) pattern for max value
            if i + 2 < self.bytecode.len() {
                if self.bytecode[i] == PUSH1 && self.bytecode[i+1] == 0x00 && self.bytecode[i+2] == NOT {
                    return true;
                }
            }
        }
        false
    }

    fn has_private_key_extraction_pattern(&self) -> bool {
        // Attempts to extract signature components
        self.has_signature_component_extraction()
    }

    fn has_signature_component_extraction(&self) -> bool {
        // Multiple BYTE operations (extracting r, s, v from signature)
        self.bytecode.iter().filter(|&&op| op == BYTE).count() >= 3
    }

    fn has_data_exfiltration(&self) -> bool {
        // Sending data to external addresses
        self.has_suspicious_external_calls() || self.has_log_exfiltration()
    }

    fn has_suspicious_external_calls(&self) -> bool {
        // CALL/STATICCALL with user data to unknown addresses
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == CALL || self.bytecode[i] == STATICCALL {
                // Check if address comes from storage (hardcoded exfiltration target)
                if self.has_sload_before(i, 15) && self.has_calldataload_before(i, 15) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_sload_before(&self, pos: usize, range: usize) -> bool {
        if pos < range { return false; }
        (pos.saturating_sub(range)..pos).any(|i| self.bytecode[i] == SLOAD)
    }

    fn has_calldataload_before(&self, pos: usize, range: usize) -> bool {
        if pos < range { return false; }
        (pos.saturating_sub(range)..pos).any(|i| self.bytecode[i] == CALLDATALOAD)
    }

    fn has_log_exfiltration(&self) -> bool {
        // LOG operations with sensitive data
        let log_count = self.bytecode.iter()
            .filter(|&&op| matches!(op, LOG0 | LOG1 | LOG2 | LOG3 | LOG4))
            .count();
        
        log_count >= 3 && self.has_calldata_in_logs()
    }

    fn has_calldata_in_logs(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if matches!(self.bytecode[i], LOG0 | LOG1 | LOG2 | LOG3 | LOG4) {
                if self.has_calldataload_before(i, 10) {
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
    fn test_malicious_snap_detection() {
        let bytecode = vec![
            PUSH1, 0x01, STATICCALL,           // ECRECOVER 1
            PUSH1, 0x01, STATICCALL,           // ECRECOVER 2
            PUSH1, 0x01, STATICCALL,           // ECRECOVER 3 (multiple signatures)
            PUSH4, 0x09, 0x5e, 0xa7, 0xb3,    // approve
            PUSH1, 0x00, NOT,                  // max value
            CALL,
            SLOAD, CALLDATALOAD,               // Load target + data
            CALL,                              // Exfiltrate
        ];
        let detector = MetamaskSnapsMaliciousPluginDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_legitimate_snap() {
        let bytecode = vec![
            CALLDATALOAD,
            PUSH1, 0x01, STATICCALL,           // Single signature check
        ];
        let detector = MetamaskSnapsMaliciousPluginDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
