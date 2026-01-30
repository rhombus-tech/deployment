use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct ArbitrumTimeboostExpressLaneAbuseDetector {
    bytecode: Vec<u8>,
}

impl ArbitrumTimeboostExpressLaneAbuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_express_lane_priority_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Contract can be exploited through Arbitrum Timeboost express lane priority manipulation, allowing MEV extraction or front-running.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_express_lane_priority_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x42 { // TIMESTAMP
                let mut has_comparison = false;
                let mut has_value_transfer = false;

                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x10 || bytecode[j] == 0x11 { has_comparison = true; }
                    if bytecode[j] == 0xF1 { has_value_transfer = true; }
                }

                if has_comparison && has_value_transfer {
                    return Some(i);
                }
            }
        }

        None
    }
}
