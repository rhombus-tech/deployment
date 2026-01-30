pub struct AaveCompoundRateArbitrageDetector {
    bytecode: Vec<u8>,
}

impl AaveCompoundRateArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_rate_arbitrage_pattern() {
            findings.push("Protocol integration: Aave/Compound rate arbitrage vulnerability detected".to_string());
        }

        if self.has_flash_loan_rate_exploit() {
            findings.push("Protocol integration: Flash loan used for rate manipulation between protocols".to_string());
        }

        if self.has_cross_protocol_leverage() {
            findings.push("Protocol integration: Excessive leverage across Aave and Compound".to_string());
        }

        findings
    }

    fn has_rate_arbitrage_pattern(&self) -> bool {
        // Check for patterns accessing both Aave and Compound
        let aave_patterns = [b"aave", b"Aave", b"AAVE", b"aToken"];
        let compound_patterns = [b"compound", b"Compound", b"cToken"];
        
        let has_aave = aave_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        let has_compound = compound_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_aave && has_compound {
            // Look for rate-related operations
            let rate_ops = [b"rate", b"borrow", b"supply", b"interest"];
            return rate_ops.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        }
        
        false
    }

    fn has_flash_loan_rate_exploit(&self) -> bool {
        // Check for flash loan + cross-protocol operations
        let flash_patterns = [b"flashLoan", b"flash", b"borrow"];
        let has_flash = flash_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_flash {
            // Check for multiple external calls (cross-protocol)
            let call_count = self.bytecode.iter()
                .filter(|&&b| b == 0xf1 || b == 0xfa) // CALL, STATICCALL
                .count();
            
            return call_count > 3;
        }
        
        false
    }

    fn has_cross_protocol_leverage(&self) -> bool {
        // Check for leverage patterns across protocols
        let leverage_patterns = [b"leverage", b"multiply", b"recurse"];
        let has_leverage = leverage_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_leverage {
            // Check for loop patterns that could amplify positions
            let loop_count = self.bytecode.iter().filter(|&&b| b == 0x57).count(); // JUMPI
            return loop_count > 2;
        }
        
        false
    }
}
