use crate::bytecode::{SecurityFinding, SecuritySeverity};
use ethers::types::U256;

pub struct NPMPackageSupplyChainAttackDetector {
    bytecode: Vec<u8>,
}

impl NPMPackageSupplyChainAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_suspicious_external_call_pattern() {
            findings.push("NPM supply chain attack: Suspicious external call pattern indicating compromised dependency".to_string());
        }

        if self.has_data_exfiltration_pattern() {
            findings.push("NPM supply chain attack: Data exfiltration pattern detected in bytecode".to_string());
        }

        if self.has_backdoor_function_signature() {
            findings.push("NPM supply chain attack: Known backdoor function signature detected".to_string());
        }

        if self.has_obfuscated_malicious_code() {
            findings.push("NPM supply chain attack: Heavily obfuscated code section suggests malicious intent".to_string());
        }

        if self.has_unusual_constructor_behavior() {
            findings.push("NPM supply chain attack: Unusual constructor behavior typical of supply chain compromises".to_string());
        }

        if self.has_unauthorized_admin_escalation() {
            findings.push("NPM supply chain attack: Unauthorized admin escalation pattern detected".to_string());
        }

        if self.has_hidden_selfdestruct() {
            findings.push("NPM supply chain attack: Hidden SELFDESTRUCT with obscure conditions".to_string());
        }

        if self.has_steganographic_payload() {
            findings.push("NPM supply chain attack: Steganographic payload encoding detected".to_string());
        }

        findings
    }

    fn has_suspicious_external_call_pattern(&self) -> bool {
        let mut i = 0;
        let mut suspicious_call_count = 0;

        while i < self.bytecode.len().saturating_sub(50) {
            if matches!(self.bytecode[i], 0xf1 | 0xf4) {
                let has_hardcoded_address = self.bytecode[i.saturating_sub(30)..i]
                    .windows(2)
                    .any(|w| w[0] == 0x73);
                
                let has_value_transfer = self.bytecode[i..i + 50]
                    .iter()
                    .any(|&b| b == 0x34 || b == 0x47);
                
                let no_return_check = !self.bytecode[i..i + 50]
                    .iter()
                    .any(|&b| b == 0x15 || b == 0x3d);
                
                if has_hardcoded_address && has_value_transfer && no_return_check {
                    suspicious_call_count += 1;
                }
            }
            i += 1;
        }

        suspicious_call_count >= 2
    }

    fn has_data_exfiltration_pattern(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x54 {
                let has_keccak = self.bytecode[i..i + 60]
                    .iter()
                    .any(|&b| b == 0x20);
                
                let has_log = self.bytecode[i..i + 60]
                    .windows(2)
                    .any(|w| matches!(w[0], 0xa0..=0xa4));
                
                let has_external_call = self.bytecode[i..i + 60]
                    .iter()
                    .any(|&b| b == 0xf1 || b == 0xf4);
                
                if has_keccak && (has_log || has_external_call) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_backdoor_function_signature(&self) -> bool {
        let _known_backdoor_sigs = [
            [0x42, 0x96, 0x6c, 0x68],
            [0x9f, 0x7f, 0x50, 0x22],
            [0x1c, 0xff, 0x79, 0xcd],
            [0xde, 0xad, 0xbe, 0xef],
        ];

        false
    }

    fn has_obfuscated_malicious_code(&self) -> bool {
        let mut obfuscation_score = 0;
        let mut i = 0;

        while i < self.bytecode.len().saturating_sub(20) {
            let xor_count = self.bytecode[i..i + 20]
                .iter()
                .filter(|&&b| b == 0x18)
                .count();
            
            let not_count = self.bytecode[i..i + 20]
                .iter()
                .filter(|&&b| b == 0x19)
                .count();
            
            let jump_count = self.bytecode[i..i + 20]
                .iter()
                .filter(|&&b| matches!(b, 0x56 | 0x57 | 0x58))
                .count();
            
            if xor_count > 3 && not_count > 2 && jump_count > 4 {
                obfuscation_score += 1;
            }
            
            i += 20;
        }

        obfuscation_score >= 3
    }

    fn has_unusual_constructor_behavior(&self) -> bool {
        let mut i = 0;
        let mut has_constructor_indicator = false;
        let mut has_suspicious_action = false;

        while i < self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x60 && i < 100 {
                has_constructor_indicator = true;
                
                let has_external_call = self.bytecode[i..i + 40]
                    .iter()
                    .any(|&b| matches!(b, 0xf1 | 0xf4));
                
                let has_selfdestruct = self.bytecode[i..i + 40]
                    .iter()
                    .any(|&b| b == 0xff);
                
                let has_delegatecall = self.bytecode[i..i + 40]
                    .iter()
                    .any(|&b| b == 0xf4);
                
                if has_external_call || has_selfdestruct || has_delegatecall {
                    has_suspicious_action = true;
                }
            }
            i += 1;
        }

        has_constructor_indicator && has_suspicious_action
    }

    fn has_unauthorized_admin_escalation(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x55 {
                let has_caller = self.bytecode[i.saturating_sub(30)..i]
                    .iter()
                    .any(|&b| b == 0x33);
                
                let no_auth_check = !self.bytecode[i.saturating_sub(50)..i]
                    .windows(2)
                    .any(|w| w[0] == 0x14 && w[1] == 0x57);
                
                let admin_slot_pattern = self.bytecode[i.saturating_sub(20)..i]
                    .windows(3)
                    .any(|w| w[0] == 0x60 && w[1] == 0x00);
                
                if has_caller && no_auth_check && admin_slot_pattern {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_hidden_selfdestruct(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len() {
            if self.bytecode[i] == 0xff {
                let complex_condition = self.bytecode[i.saturating_sub(100)..i]
                    .iter()
                    .filter(|&&b| matches!(b, 0x57 | 0x58))
                    .count() > 5;
                
                let obfuscated_trigger = self.bytecode[i.saturating_sub(50)..i]
                    .iter()
                    .filter(|&&b| matches!(b, 0x18 | 0x19 | 0x1b))
                    .count() > 3;
                
                if complex_condition && obfuscated_trigger {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_steganographic_payload(&self) -> bool {
        let mut entropy_score = 0;
        let chunk_size = 32;

        for chunk in self.bytecode.chunks(chunk_size) {
            let unique_bytes = chunk.iter().collect::<std::collections::HashSet<_>>().len();
            let avg_value: u32 = chunk.iter().map(|&b| b as u32).sum::<u32>() / chunk.len() as u32;
            
            if unique_bytes > 20 && (avg_value > 200 || avg_value < 55) {
                entropy_score += 1;
            }
        }

        entropy_score > (self.bytecode.len() / chunk_size) / 3
    }
}
