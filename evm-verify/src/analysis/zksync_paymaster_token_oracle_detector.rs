pub struct ZksyncPaymasterTokenOracleDetector {
    bytecode: Vec<u8>,
}

impl ZksyncPaymasterTokenOracleDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_oracle_manipulation() {
            findings.push("zkSync Paymaster: Token oracle can be manipulated".to_string());
        }

        if self.has_stale_price_usage() {
            findings.push("zkSync Paymaster: Stale oracle prices used for gas payment".to_string());
        }

        if self.has_price_slippage_exploit() {
            findings.push("zkSync Paymaster: Price slippage during gas payment".to_string());
        }

        findings
    }

    fn has_oracle_manipulation(&self) -> bool {
        let paymaster_patterns = [b"paymaster", b"Paymaster", b"paymasterInput"];
        let has_paymaster = paymaster_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_paymaster {
            let oracle_patterns = [b"oracle", b"price", b"getPrice"];
            let has_oracle = oracle_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_oracle {
                // Check for freshness validation
                let freshness_patterns = [b"timestamp", b"updatedAt", b"age"];
                let has_freshness = freshness_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_freshness;
            }
        }
        
        false
    }

    fn has_stale_price_usage(&self) -> bool {
        let price_patterns = [b"tokenPrice", b"getPrice", b"latestPrice"];
        let has_price_fetch = price_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_price_fetch {
            // Look for TIMESTAMP opcode usage
            let has_timestamp_check = self.bytecode.iter().any(|&b| b == 0x42); // TIMESTAMP
            
            return !has_timestamp_check;
        }
        
        false
    }

    fn has_price_slippage_exploit(&self) -> bool {
        let payment_patterns = [b"payForTransaction", b"validateAndPayForPaymasterTransaction"];
        let has_payment = payment_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_payment {
            // Check for slippage protection
            let slippage_patterns = [b"minAmount", b"maxAmount", b"slippage"];
            let has_slippage = slippage_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_slippage;
        }
        
        false
    }
}
