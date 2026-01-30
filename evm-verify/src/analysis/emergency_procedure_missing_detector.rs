pub struct EmergencyProcedureMissingDetector {
    bytecode: Vec<u8>,
}

impl EmergencyProcedureMissingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.lacks_pause_mechanism() {
            findings.push("Emergency procedure: No pause mechanism for emergency situations".to_string());
        }

        if self.lacks_emergency_withdrawal() {
            findings.push("Emergency procedure: No emergency withdrawal function for fund recovery".to_string());
        }

        if self.lacks_circuit_breaker() {
            findings.push("Emergency procedure: No circuit breaker for abnormal conditions".to_string());
        }

        findings
    }

    fn lacks_pause_mechanism(&self) -> bool {
        // Check for valuable operations without pause capability
        let has_value_operations = self.bytecode.iter().any(|&b| b == 0xf1 || b == 0xf0); // CALL or CREATE
        
        if has_value_operations {
            // Look for pause/unpause patterns
            let pause_patterns = [b"pause", b"Pause", b"paused", b"whenNotPaused"];
            let has_pause = pause_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_pause;
        }
        
        false
    }

    fn lacks_emergency_withdrawal(&self) -> bool {
        // Check for funds handling without emergency withdrawal
        let has_fund_operations = self.bytecode.windows(8).any(|w| 
            w == b"transfer" || w == b"withdraw" || w == b"balance"
        );
        
        if has_fund_operations {
            // Look for emergency withdrawal patterns
            let emergency_patterns = [
                b"emergency",
                b"rescue",
                b"recover",
                b"sweep",
            ];
            
            let has_emergency = emergency_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_emergency;
        }
        
        false
    }

    fn lacks_circuit_breaker(&self) -> bool {
        // Check for rate-sensitive operations without circuit breaker
        let has_sensitive_ops = self.bytecode.windows(4).any(|w| w == b"swap" || w == b"mint");
        
        if has_sensitive_ops {
            // Look for circuit breaker patterns
            let breaker_patterns = [
                b"threshold",
                b"limit",
                b"maxAmount",
                b"cap",
            ];
            
            let has_breaker = breaker_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_breaker;
        }
        
        false
    }
}
