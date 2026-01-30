use crate::bytecode::{SecurityFinding, SecuritySeverity};
use ethers::types::U256;

pub struct TravelRuleThresholdSplittingDetector {
    bytecode: Vec<u8>,
}

impl TravelRuleThresholdSplittingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_amount_splitting_pattern() {
            findings.push("Travel rule bypass: Amount splitting to stay below reporting threshold".to_string());
        }

        if self.has_multiple_small_transfers() {
            findings.push("Travel rule bypass: Multiple sequential small transfers instead of single large transfer".to_string());
        }

        if self.has_time_delayed_splitting() {
            findings.push("Travel rule bypass: Time-delayed transfer splitting to avoid aggregation".to_string());
        }

        if self.has_recipient_rotation() {
            findings.push("Travel rule bypass: Rotating through multiple recipient addresses".to_string());
        }

        if self.has_batch_transfer_splitting() {
            findings.push("Travel rule bypass: Batch transfers split to stay below threshold per recipient".to_string());
        }

        if self.has_threshold_calculation() {
            findings.push("Travel rule bypass: Hardcoded threshold value suggests intentional splitting".to_string());
        }

        if self.has_intermediary_hop_splitting() {
            findings.push("Travel rule bypass: Using intermediary contracts to split large transfers".to_string());
        }

        if self.has_circular_splitting_pattern() {
            findings.push("Travel rule bypass: Circular transfer pattern to obfuscate total amount".to_string());
        }

        findings
    }

    fn has_amount_splitting_pattern(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x04 {
                let has_comparison = self.bytecode[i..i + 40]
                    .windows(2)
                    .any(|w| w[0] == 0x10 || w[0] == 0x11);
                
                let has_branch = self.bytecode[i..i + 40]
                    .windows(2)
                    .any(|w| w[0] == 0x57);
                
                let has_transfer = self.bytecode[i..i + 40]
                    .windows(2)
                    .any(|w| w[0] == 0xa9 || w[0] == 0xf1);
                
                if has_comparison && has_branch && has_transfer {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_multiple_small_transfers(&self) -> bool {
        let mut transfer_count = 0;
        let mut loop_indicator = false;

        for i in 0..self.bytecode.len() {
            match self.bytecode[i] {
                0xa9 | 0xf1 => transfer_count += 1,
                0x56 => loop_indicator = true,
                _ => {}
            }
        }

        transfer_count >= 3 && loop_indicator
    }

    fn has_time_delayed_splitting(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x42 {
                let has_addition = self.bytecode[i..i + 50]
                    .windows(2)
                    .any(|w| w[0] == 0x01);
                
                let has_storage_write = self.bytecode[i..i + 50]
                    .windows(2)
                    .any(|w| w[0] == 0x55);
                
                let has_transfer = self.bytecode[i..i + 50]
                    .windows(2)
                    .any(|w| w[0] == 0xa9 || w[0] == 0xf1);
                
                if has_addition && has_storage_write && has_transfer {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_recipient_rotation(&self) -> bool {
        let mut i = 0;
        let mut address_load_count = 0;

        while i < self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {
                let has_increment = self.bytecode[i..i + 30]
                    .windows(2)
                    .any(|w| w[0] == 0x01 && w[1] == 0x55);
                
                if has_increment {
                    address_load_count += 1;
                }
            }
            i += 1;
        }

        address_load_count >= 3
    }

    fn has_batch_transfer_splitting(&self) -> bool {
        let batch_transfer_sigs = [
            [0xf2, 0xf0, 0x38, 0x7f],
            [0x1e, 0x83, 0x40, 0x9b],
        ];

        for i in 0..self.bytecode.len().saturating_sub(4) {
            for sig in &batch_transfer_sigs {
                if self.bytecode[i..i + 4] == *sig {
                    let has_amount_check = self.bytecode[i..i.min(i + 100)]
                        .windows(2)
                        .any(|w| w[0] == 0x10 || w[0] == 0x11);
                    
                    if has_amount_check {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_threshold_calculation(&self) -> bool {
        let threshold_values = [
            vec![0x60, 0x27, 0x10],
            vec![0x61, 0x03, 0xe8],
            vec![0x62, 0x00, 0x00, 0x2e, 0xe0],
        ];

        for threshold in &threshold_values {
            for i in 0..self.bytecode.len().saturating_sub(threshold.len()) {
                if self.bytecode[i..i + threshold.len()] == threshold[..] {
                    let has_comparison = self.bytecode[i..i.min(i + 30)]
                        .windows(2)
                        .any(|w| w[0] == 0x10 || w[0] == 0x11);
                    
                    if has_comparison {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_intermediary_hop_splitting(&self) -> bool {
        let mut i = 0;
        let mut call_chain_length = 0;

        while i < self.bytecode.len().saturating_sub(60) {
            if matches!(self.bytecode[i], 0xf1 | 0xf4) {
                let has_value = self.bytecode[i..i + 60]
                    .windows(2)
                    .any(|w| w[0] == 0x34 || w[0] == 0x47);
                
                let has_next_call = self.bytecode[i + 1..i + 60]
                    .windows(2)
                    .any(|w| matches!(w[0], 0xf1 | 0xf4));
                
                if has_value && has_next_call {
                    call_chain_length += 1;
                }
            }
            i += 1;
        }

        call_chain_length >= 2
    }

    fn has_circular_splitting_pattern(&self) -> bool {
        let mut i = 0;
        let mut pattern_indicators = 0;

        while i < self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i] == 0xf1 {
                let has_sender_check = self.bytecode[i..i + 80]
                    .windows(2)
                    .any(|w| w[0] == 0x33);
                
                let has_origin_check = self.bytecode[i..i + 80]
                    .windows(2)
                    .any(|w| w[0] == 0x32);
                
                let has_loop = self.bytecode[i..i + 80]
                    .windows(2)
                    .any(|w| w[0] == 0x56);
                
                if has_sender_check && has_origin_check && has_loop {
                    pattern_indicators += 1;
                }
            }
            i += 1;
        }

        pattern_indicators >= 2
    }
}
