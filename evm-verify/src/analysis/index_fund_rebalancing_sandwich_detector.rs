pub struct IndexFundRebalancingSandwichDetector {
    bytecode: Vec<u8>,
}

impl IndexFundRebalancingSandwichDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_rebalancing_frontrun() {
            findings.push("Index fund: Rebalancing operations can be sandwiched".to_string());
        }

        if self.has_weight_adjustment_exploit() {
            findings.push("Index fund: Weight adjustments vulnerable to manipulation".to_string());
        }

        if self.has_slippage_accumulation() {
            findings.push("Index fund: Slippage accumulates during multi-asset rebalancing".to_string());
        }

        findings
    }

    fn has_rebalancing_frontrun(&self) -> bool {
        let rebalance_patterns = [b"rebalance", b"Rebalance", b"adjust"];
        let has_rebalance = rebalance_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_rebalance {
            // Check for swap operations
            let swap_patterns = [b"swap", b"trade", b"exchange"];
            let has_swap = swap_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_swap {
                // Check for frontrun protection (private mempools, etc.)
                let protection_patterns = [b"private", b"flashbots", b"commit"];
                let has_protection = protection_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_protection;
            }
        }
        
        false
    }

    fn has_weight_adjustment_exploit(&self) -> bool {
        let weight_patterns = [b"weight", b"Weight", b"allocation"];
        let has_weight = weight_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_weight {
            // Check for index/fund patterns
            let index_patterns = [b"index", b"Index", b"fund"];
            let has_index = index_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_index {
                // Check for gradual adjustment protection
                let gradual_patterns = [b"gradual", b"delay", b"cooldown"];
                let has_gradual = gradual_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_gradual;
            }
        }
        
        false
    }

    fn has_slippage_accumulation(&self) -> bool {
        let multi_patterns = [b"multi", b"batch", b"multiple"];
        let has_multi = multi_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_multi {
            // Check for swap operations
            let swap_patterns = [b"swap", b"trade"];
            let has_swap = swap_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_swap {
                // Check for slippage accumulation protection
                let slippage_patterns = [b"totalSlippage", b"maxSlippage", b"slippageLimit"];
                let has_slippage = slippage_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_slippage;
            }
        }
        
        false
    }
}
