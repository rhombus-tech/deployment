pub struct PreconfirmationBasedContractDetector {
    bytecode: Vec<u8>,
}

impl PreconfirmationBasedContractDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_preconf_dependency() {
            findings.push("Preconfirmation: Contract depends on preconfirmation guarantees".to_string());
        }

        if self.has_preconf_payment_manipulation() {
            findings.push("Preconfirmation: Preconfirmation payment logic can be manipulated".to_string());
        }

        if self.has_reorg_vulnerability() {
            findings.push("Preconfirmation: Vulnerable to chain reorganizations despite preconfirmations".to_string());
        }

        findings
    }

    fn has_preconf_dependency(&self) -> bool {
        let preconf_patterns = [b"preconf", b"Preconf", b"preCommit", b"earlyCommit"];
        let has_preconf = preconf_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_preconf {
            // Check for block number or timestamp dependencies
            let has_blocknumber = self.bytecode.iter().any(|&b| b == 0x43); // NUMBER
            let has_timestamp = self.bytecode.iter().any(|&b| b == 0x42); // TIMESTAMP
            
            return has_blocknumber || has_timestamp;
        }
        
        false
    }

    fn has_preconf_payment_manipulation(&self) -> bool {
        let payment_patterns = [b"payment", b"fee", b"tip", b"priority"];
        let has_payment = payment_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_payment {
            // Check for GASPRICE usage
            let has_gasprice = self.bytecode.iter().any(|&b| b == 0x3a);
            
            // Check for value transfers
            let has_call = self.bytecode.iter().any(|&b| b == 0xf1);
            
            return has_gasprice && has_call;
        }
        
        false
    }

    fn has_reorg_vulnerability(&self) -> bool {
        let finality_patterns = [b"finalize", b"confirm", b"irreversible"];
        let has_finality_check = finality_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if !has_finality_check {
            // Check if contract performs irreversible operations
            let irreversible_patterns = [b"burn", b"destroy", b"transfer"];
            let has_irreversible = irreversible_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return has_irreversible;
        }
        
        false
    }
}
