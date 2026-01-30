pub struct InclusionListCensorshipDetector {
    bytecode: Vec<u8>,
}

impl InclusionListCensorshipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_inclusion_list_bypass() {
            findings.push("Inclusion list: Mandatory inclusion list can be bypassed".to_string());
        }

        if self.has_transaction_filtering() {
            findings.push("Inclusion list: Transaction filtering before inclusion list processing".to_string());
        }

        if self.has_censorship_mechanism() {
            findings.push("Inclusion list: Censorship mechanism detected in transaction ordering".to_string());
        }

        findings
    }

    fn has_inclusion_list_bypass(&self) -> bool {
        let inclusion_patterns = [b"inclusion", b"Inclusion", b"forceInclude", b"mandatoryTx"];
        let has_inclusion = inclusion_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_inclusion {
            // Check for conditional logic that might skip inclusion
            let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
            
            if jumpi_count > 0 {
                // Look for admin/privileged bypass
                let admin_patterns = [b"owner", b"admin", b"onlyOwner"];
                let has_admin = admin_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return has_admin;
            }
        }
        
        false
    }

    fn has_transaction_filtering(&self) -> bool {
        let filter_patterns = [b"filter", b"Filter", b"blacklist", b"censor"];
        let has_filter = filter_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_filter {
            // Check for transaction selection logic
            let has_origin = self.bytecode.iter().any(|&b| b == 0x32); // ORIGIN
            let has_caller = self.bytecode.iter().any(|&b| b == 0x33); // CALLER
            
            return has_origin || has_caller;
        }
        
        false
    }

    fn has_censorship_mechanism(&self) -> bool {
        let censor_patterns = [b"censor", b"block", b"reject", b"exclude"];
        let has_censor = censor_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_censor {
            // Check for address-based filtering
            let has_storage = self.bytecode.iter().any(|&b| b == 0x54); // SLOAD
            
            // Check for conditional execution
            let has_jumpi = self.bytecode.iter().any(|&b| b == 0x57);
            
            return has_storage && has_jumpi;
        }
        
        false
    }
}
