pub struct SilentFailureUnmonitoredFunctionDetector {
    bytecode: Vec<u8>,
}

impl SilentFailureUnmonitoredFunctionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_unchecked_external_calls() {
            findings.push("Silent failure: Unchecked external calls without monitoring".to_string());
        }

        if self.has_missing_event_emission() {
            findings.push("Silent failure: Critical functions missing event emissions".to_string());
        }

        if self.has_unmonitored_state_changes() {
            findings.push("Silent failure: State changes without monitoring hooks".to_string());
        }

        findings
    }

    fn has_unchecked_external_calls(&self) -> bool {
        for i in 0..self.bytecode.len().saturating_sub(2) {
            if (self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4) {
                if i + 1 < self.bytecode.len() && self.bytecode[i + 1] != 0x15 {
                    return true;
                }
            }
        }
        false
    }

    fn has_missing_event_emission(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xf1 || b == 0xf4).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xa0 && b <= 0xa4).count();
        
        call_count > 5 && log_count < 3
    }

    fn has_unmonitored_state_changes(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xa0 && b <= 0xa4).count();
        
        sstore_count > 10 && log_count < 5
    }
}
