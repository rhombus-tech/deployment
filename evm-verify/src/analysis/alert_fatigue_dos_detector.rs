pub struct AlertFatigueDosDetector {
    bytecode: Vec<u8>,
}

impl AlertFatigueDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_excessive_event_emission() {
            findings.push("Alert fatigue: Excessive event emission pattern detected".to_string());
        }

        if self.has_spam_alert_vulnerability() {
            findings.push("Alert fatigue: Spam alert vulnerability in monitoring".to_string());
        }

        if self.has_alert_storm_trigger() {
            findings.push("Alert fatigue: Alert storm trigger pattern detected".to_string());
        }

        findings
    }

    fn has_excessive_event_emission(&self) -> bool {
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xa0 && b <= 0xa4).count();
        
        log_count > 50
    }

    fn has_spam_alert_vulnerability(&self) -> bool {
        let event_patterns: &[&[u8]] = &[
            b"emit",
            b"Event",
            b"log",
            b"alert",
        ];
        
        let mut pattern_count = 0;
        for pattern in event_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                pattern_count += 1;
            }
        }
        
        pattern_count >= 2
    }

    fn has_alert_storm_trigger(&self) -> bool {
        let loop_patterns: &[&[u8]] = &[
            b"for",
            b"while",
            b"loop",
        ];
        
        for pattern in loop_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        for i in 0..self.bytecode.len().saturating_sub(3) {
            if self.bytecode[i] == 0x56 || self.bytecode[i] == 0x57 {
                return true;
            }
        }
        
        false
    }
}
