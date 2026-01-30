use crate::bytecode::opcodes::*;

pub struct WalletconnectSessionHijackingDetector {
    bytecode: Vec<u8>,
}

impl WalletconnectSessionHijackingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_session_management()
            && (self.has_session_fixation() || self.has_signature_reuse())
    }

    fn has_session_management(&self) -> bool {
        // Session token storage/retrieval
        self.has_session_storage() && self.has_session_validation()
    }

    fn has_session_storage(&self) -> bool {
        // SSTORE for session data
        self.bytecode.iter().any(|&op| op == SSTORE)
    }

    fn has_session_validation(&self) -> bool {
        // SLOAD followed by comparison
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == SLOAD {
                for j in i+1..i.min(self.bytecode.len()).min(i+8) {
                    if matches!(self.bytecode[j], EQ | ISZERO) {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_session_fixation(&self) -> bool {
        // Predictable session IDs
        self.has_weak_session_generation()
    }

    fn has_weak_session_generation(&self) -> bool {
        // Using only TIMESTAMP or BLOCKNUMBER for session ID
        let mut has_timestamp = false;
        let mut has_sstore = false;

        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if opcode == TIMESTAMP || opcode == BLOCKNUMBER {
                has_timestamp = true;
            }
            if has_timestamp && opcode == SSTORE {
                // No additional randomness added
                if !self.has_randomness_before(i) {
                    has_sstore = true;
                }
            }
        }

        has_timestamp && has_sstore
    }

    fn has_randomness_before(&self, pos: usize) -> bool {
        if pos < 10 { return false; }
        
        for i in (pos.saturating_sub(10))..pos {
            // Check for randomness sources
            if matches!(self.bytecode[i], KECCAK256 | BLOCKHASH) {
                return true;
            }
        }
        false
    }

    fn has_signature_reuse(&self) -> bool {
        // Signature validation without nonce
        self.has_signature_validation() && !self.has_nonce_tracking()
    }

    fn has_signature_validation(&self) -> bool {
        // ECRECOVER usage
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == PUSH1 && i + 1 < self.bytecode.len() {
                if self.bytecode[i+1] == 0x01 { // ECRECOVER precompile
                    for j in i+2..i.min(self.bytecode.len()).min(i+8) {
                        if self.bytecode[j] == STATICCALL {
                            return true;
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_nonce_tracking(&self) -> bool {
        // Nonce increment pattern
        let mut has_sload = false;
        let mut has_add = false;
        let mut has_sstore = false;

        for &opcode in &self.bytecode {
            if opcode == SLOAD { has_sload = true; }
            if opcode == ADD && has_sload { has_add = true; }
            if opcode == SSTORE && has_add { has_sstore = true; }
        }

        has_sload && has_add && has_sstore
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_hijacking() {
        let bytecode = vec![
            TIMESTAMP,              // Weak session ID
            SSTORE,                 // Store session
            PUSH1, 0x01,            // ECRECOVER
            STATICCALL,             // Validate signature (no nonce)
        ];
        let detector = WalletconnectSessionHijackingDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_secure_session() {
        let bytecode = vec![
            TIMESTAMP, KECCAK256,   // Random session ID
            SLOAD, ADD, SSTORE,     // Nonce tracking
            PUSH1, 0x01, STATICCALL, // Signature validation
        ];
        let detector = WalletconnectSessionHijackingDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
