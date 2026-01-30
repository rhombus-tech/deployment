use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct ArbitrumTimeboostSequencerLatencyArbitrageDetector {
    bytecode: Vec<u8>,
}

impl ArbitrumTimeboostSequencerLatencyArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_sequencer_latency_exploit() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Contract vulnerable to sequencer latency arbitrage through Timeboost, allowing time-based MEV extraction.".to_string(),
                pc,
                confidence: 0.80,
            });
        }

        findings
    }

    fn detect_sequencer_latency_exploit(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(35) {
            if bytecode[i] == 0x43 { // NUMBER (block number)
                let mut has_price_check = false;
                let mut has_swap = false;

                for j in i+1..std::cmp::min(i+30, bytecode.len()) {
                    if bytecode[j] == 0xFA { has_price_check = true; } // STATICCALL
                    if bytecode[j] == 0xF1 { has_swap = true; } // CALL
                }

                if has_price_check && has_swap {
                    return Some(i);
                }
            }
        }

        None
    }
}
