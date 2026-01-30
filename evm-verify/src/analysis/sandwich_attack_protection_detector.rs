pub struct SandwichAttackProtectionDetector {
    bytecode: Vec<u8>,
}

impl SandwichAttackProtectionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_missing_slippage_protection() {
            findings.push("Sandwich attack: Missing slippage protection on swaps".to_string());
        }

        if self.has_no_deadline_check() {
            findings.push("Sandwich attack: No transaction deadline enforcement".to_string());
        }

        if self.has_vulnerable_price_calculation() {
            findings.push("Sandwich attack: Price calculation vulnerable to manipulation".to_string());
        }

        findings
    }

    fn has_missing_slippage_protection(&self) -> bool {
        let swap_patterns = [b"swap", b"Swap", b"exchange"];
        let has_swap = swap_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_swap {
            let amount_patterns = [b"amountOut", b"amountIn", b"amount"];
            let has_amount = amount_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_amount {
                let slippage_patterns = [b"minAmount", b"minOut", b"amountOutMin"];
                let has_slippage = slippage_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_slippage;
            }
        }
        
        false
    }

    fn has_no_deadline_check(&self) -> bool {
        let swap_patterns = [b"swap", b"trade", b"exchange"];
        let has_swap = swap_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_swap {
            let has_timestamp = self.bytecode.iter().any(|&b| b == 0x42);
            
            if has_timestamp {
                let deadline_patterns = [b"deadline", b"expiry", b"validUntil"];
                let has_deadline = deadline_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_deadline;
            }
        }
        
        false
    }

    fn has_vulnerable_price_calculation(&self) -> bool {
        let price_patterns = [b"price", b"Price", b"getPrice"];
        let has_price = price_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_price {
            let reserve_patterns = [b"reserve", b"Reserve", b"balance"];
            let has_reserve = reserve_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_reserve {
                let twap_patterns = [b"twap", b"average", b"oracle"];
                let has_twap = twap_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_twap;
            }
        }
        
        false
    }
}
