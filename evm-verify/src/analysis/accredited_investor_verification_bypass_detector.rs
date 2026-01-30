use crate::bytecode::{SecurityFinding, SecuritySeverity};
use ethers::types::U256;

pub struct AccreditedInvestorVerificationBypassDetector {
    bytecode: Vec<u8>,
}

impl AccreditedInvestorVerificationBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_missing_kyc_verification() {
            findings.push("Accredited investor bypass: Missing KYC/accreditation verification before investment".to_string());
        }

        if self.has_hardcoded_whitelist_bypass() {
            findings.push("Accredited investor bypass: Hardcoded whitelist allows unauthorized access".to_string());
        }

        if self.has_self_attestation_without_verification() {
            findings.push("Accredited investor bypass: Self-attestation without third-party verification".to_string());
        }

        if self.has_oracle_verification_bypass() {
            findings.push("Accredited investor bypass: Missing oracle verification for accreditation status".to_string());
        }

        if self.has_timestamp_manipulation_bypass() {
            findings.push("Accredited investor bypass: Timestamp manipulation allows expired accreditation".to_string());
        }

        if self.has_proxy_investment_bypass() {
            findings.push("Accredited investor bypass: Proxy investment mechanism circumvents verification".to_string());
        }

        if self.has_amount_threshold_bypass() {
            findings.push("Accredited investor bypass: Investment splitting bypasses accreditation threshold".to_string());
        }

        if self.has_signature_replay_bypass() {
            findings.push("Accredited investor bypass: Signature replay allows unauthorized investor access".to_string());
        }

        findings
    }

    fn has_missing_kyc_verification(&self) -> bool {
        let mut has_investment = false;
        let mut has_verification = false;

        for i in 0..self.bytecode.len() {
            match self.bytecode[i] {
                0xa9 | 0xf1 if self.has_value_transfer_context(i) => {
                    has_investment = true;
                }
                0xfa => {
                    has_verification = true;
                }
                _ => {}
            }
        }

        has_investment && !has_verification
    }

    fn has_value_transfer_context(&self, pos: usize) -> bool {
        if pos < 20 {
            return false;
        }
        self.bytecode[pos.saturating_sub(20)..pos]
            .iter()
            .any(|&b| b == 0x34 || b == 0x47)
    }

    fn has_hardcoded_whitelist_bypass(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x73 {
                let has_equality_check = self.bytecode[i..i + 40]
                    .windows(2)
                    .any(|w| w[0] == 0x14);
                
                let has_no_storage_check = !self.bytecode[i..i + 40]
                    .iter()
                    .any(|&b| b == 0x54);
                
                if has_equality_check && has_no_storage_check {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_self_attestation_without_verification(&self) -> bool {
        let mut i = 0;
        let mut has_caller_provided_data = false;
        let mut has_external_verification = false;

        while i < self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x35 {
                let has_storage_write = self.bytecode[i..i + 50]
                    .windows(2)
                    .any(|w| w[0] == 0x55);
                
                if has_storage_write {
                    has_caller_provided_data = true;
                }
            }
            
            if self.bytecode[i] == 0xfa {
                has_external_verification = true;
            }
            
            i += 1;
        }

        has_caller_provided_data && !has_external_verification
    }

    fn has_oracle_verification_bypass(&self) -> bool {
        let invest_signatures = [
            [0x6e, 0x55, 0x3f, 0x65],
            [0xa6, 0xf9, 0xda, 0xe8],
        ];

        for i in 0..self.bytecode.len().saturating_sub(4) {
            for sig in &invest_signatures {
                if self.bytecode[i..i + 4] == *sig {
                    let has_staticcall = self.bytecode[i..i.min(i + 100)]
                        .iter()
                        .any(|&b| b == 0xfa);
                    
                    if !has_staticcall {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_timestamp_manipulation_bypass(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 {
                let has_less_than_check = self.bytecode[i..i + 40]
                    .windows(2)
                    .any(|w| w[0] == 0x10);
                
                let no_sufficient_margin = !self.bytecode[i..i + 40]
                    .windows(3)
                    .any(|w| matches!(w[0], 0x60..=0x62) && w[1] > 0x0e && w[2] == 0x10);
                
                if has_less_than_check && no_sufficient_margin {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_proxy_investment_bypass(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0xf4 {
                let has_investment_call = self.bytecode[i..i + 60]
                    .windows(2)
                    .any(|w| w[0] == 0x34 || w[0] == 0xa9);
                
                let no_prior_verification = !self.bytecode[i.saturating_sub(50)..i]
                    .iter()
                    .any(|&b| b == 0xfa || b == 0x54);
                
                if has_investment_call && no_prior_verification {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_amount_threshold_bypass(&self) -> bool {
        let mut i = 0;
        let mut small_investment_pattern = 0;

        while i < self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x10 {
                let has_loop = self.bytecode[i..i + 50]
                    .windows(2)
                    .any(|w| w[0] == 0x56);
                
                let has_transfer = self.bytecode[i..i + 50]
                    .windows(2)
                    .any(|w| w[0] == 0xa9 || w[0] == 0xf1);
                
                if has_loop && has_transfer {
                    small_investment_pattern += 1;
                }
            }
            i += 1;
        }

        small_investment_pattern >= 2
    }

    fn has_signature_replay_bypass(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i] == 0x01 {
                let has_signature_recovery = self.bytecode[i..i + 80]
                    .windows(2)
                    .any(|w| w[0] == 0x01);
                
                let no_nonce_check = !self.bytecode[i..i + 80]
                    .windows(2)
                    .any(|w| w[0] == 0x54 && w[1] == 0x55);
                
                let no_timestamp_check = !self.bytecode[i..i + 80]
                    .iter()
                    .any(|&b| b == 0x42);
                
                if has_signature_recovery && no_nonce_check && no_timestamp_check {
                    return true;
                }
            }
            i += 1;
        }
        false
    }
}
