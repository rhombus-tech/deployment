use crate::bytecode::opcodes::*;

pub struct Web3modalPhishingRedirectDetector {
    bytecode: Vec<u8>,
}

impl Web3modalPhishingRedirectDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_redirect_pattern()
            && (self.has_malicious_callback() || self.has_domain_spoofing())
    }

    fn has_redirect_pattern(&self) -> bool {
        // Event emissions with URL/callback data
        self.has_log_with_data()
    }

    fn has_log_with_data(&self) -> bool {
        // LOG operations (event emissions)
        self.bytecode.iter()
            .any(|&op| matches!(op, LOG1 | LOG2 | LOG3 | LOG4))
    }

    fn has_malicious_callback(&self) -> bool {
        // Callback URL manipulation
        self.has_unchecked_callback_data()
    }

    fn has_unchecked_callback_data(&self) -> bool {
        // CALLDATALOAD without validation before LOG
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == CALLDATALOAD {
                let mut has_validation = false;
                let mut has_log = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+12) {
                    if matches!(self.bytecode[j], EQ | LT | GT) {
                        has_validation = true;
                    }
                    if matches!(self.bytecode[j], LOG1 | LOG2 | LOG3 | LOG4) {
                        has_log = true;
                    }
                }

                if has_log && !has_validation {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_domain_spoofing(&self) -> bool {
        // Multiple external calls suggesting redirection
        self.has_multiple_external_calls() && self.has_address_manipulation()
    }

    fn has_multiple_external_calls(&self) -> bool {
        let call_count = self.bytecode.iter()
            .filter(|&&op| op == CALL || op == STATICCALL)
            .count();
        
        call_count >= 2
    }

    fn has_address_manipulation(&self) -> bool {
        // Address loaded from calldata or computed
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == CALLDATALOAD {
                // Address extraction from calldata
                for j in i+1..i.min(self.bytecode.len()).min(i+10) {
                    if self.bytecode[j] == AND { // Address masking
                        for k in j+1..j.min(self.bytecode.len()).min(j+5) {
                            if self.bytecode[k] == CALL {
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
    fn test_phishing_redirect() {
        let bytecode = vec![
            CALLDATALOAD,           // Load callback URL
            LOG2,                   // Emit without validation
            CALLDATALOAD, AND,      // Load malicious address
            CALL,                   // Redirect to phishing site
        ];
        let detector = Web3modalPhishingRedirectDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_safe_redirect() {
        let bytecode = vec![
            CALLDATALOAD,
            EQ,                     // Validate callback
            LOG2,
        ];
        let detector = Web3modalPhishingRedirectDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
