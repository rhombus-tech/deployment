pub struct EmergencyShutdownBypassDetector {
    bytecode: Vec<u8>,
}

impl EmergencyShutdownBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_shutdown_bypass_vulnerability() {
            findings.push("Emergency response: Emergency shutdown bypass vulnerability detected".to_string());
        }

        if self.has_pause_mechanism_weakness() {
            findings.push("Emergency response: Pause mechanism weakness detected".to_string());
        }

        if self.has_kill_switch_failure() {
            findings.push("Emergency response: Kill switch failure risk detected".to_string());
        }

        findings
    }

    fn has_shutdown_bypass_vulnerability(&self) -> bool {
        let shutdown_patterns: &[&[u8]] = &[
            b"shutdown",
            b"emergencyShutdown",
            b"terminate",
            b"disable",
        ];
        
        for pattern in shutdown_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_pause_mechanism_weakness(&self) -> bool {
        let pause_patterns: &[&[u8]] = &[
            b"pause",
            b"unpause",
            b"paused",
            b"whenNotPaused",
        ];
        
        for pattern in pause_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_kill_switch_failure(&self) -> bool {
        let kill_patterns: &[&[u8]] = &[
            b"killSwitch",
            b"emergencyStop",
            b"haltOperations",
            b"freezeContract",
        ];
        
        for pattern in kill_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }
}
