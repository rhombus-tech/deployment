pub struct BuilderPaymentManipulationDetector {
    bytecode: Vec<u8>,
}

impl BuilderPaymentManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_builder_payment_exploit() {
            findings.push("MEV Builder: Builder payment can be manipulated".to_string());
        }

        if self.has_coinbase_transfer_manipulation() {
            findings.push("MEV Builder: Coinbase transfers vulnerable to manipulation".to_string());
        }

        if self.has_priority_fee_extraction() {
            findings.push("MEV Builder: Excessive priority fee extraction detected".to_string());
        }

        findings
    }

    fn has_builder_payment_exploit(&self) -> bool {
        let builder_patterns = [b"builder", b"Builder", b"block.coinbase"];
        let has_builder = builder_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_builder {
            // Check for COINBASE opcode (0x41)
            let has_coinbase = self.bytecode.iter().any(|&b| b == 0x41);
            
            if has_coinbase {
                // Look for value transfers to coinbase
                let has_call = self.bytecode.iter().any(|&b| b == 0xf1); // CALL
                return has_call;
            }
        }
        
        false
    }

    fn has_coinbase_transfer_manipulation(&self) -> bool {
        let has_coinbase = self.bytecode.iter().any(|&b| b == 0x41); // COINBASE
        
        if has_coinbase {
            // Check for conditional coinbase payments
            let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
            
            if jumpi_count > 0 {
                // Look for SELFBALANCE to manipulate amounts
                let has_selfbalance = self.bytecode.iter().any(|&b| b == 0x47);
                return has_selfbalance;
            }
        }
        
        false
    }

    fn has_priority_fee_extraction(&self) -> bool {
        // Check for GASPRICE opcode usage
        let has_gasprice = self.bytecode.iter().any(|&b| b == 0x3a); // GASPRICE
        
        if has_gasprice {
            // Check if gas price affects payment logic
            let has_coinbase = self.bytecode.iter().any(|&b| b == 0x41);
            let has_call = self.bytecode.iter().any(|&b| b == 0xf1);
            
            return has_coinbase && has_call;
        }
        
        false
    }
}
