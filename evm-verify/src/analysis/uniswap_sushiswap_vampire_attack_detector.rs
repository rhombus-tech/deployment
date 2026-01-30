pub struct UniswapSushiswapVampireAttackDetector {
    bytecode: Vec<u8>,
}

impl UniswapSushiswapVampireAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_liquidity_migration_exploit() {
            findings.push("Vampire attack: Liquidity migration vulnerable to exploitation".to_string());
        }

        if self.has_incentive_manipulation() {
            findings.push("Vampire attack: Reward incentives can be manipulated during migration".to_string());
        }

        if self.has_pool_draining_pattern() {
            findings.push("Vampire attack: Pool draining attack pattern detected".to_string());
        }

        findings
    }

    fn has_liquidity_migration_exploit(&self) -> bool {
        let migration_patterns = [b"migrate", b"removeLiquidity", b"addLiquidity"];
        let has_migration = migration_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_migration {
            let dex_patterns = [b"uniswap", b"Uniswap", b"sushiswap", b"Sushiswap"];
            let dex_count = dex_patterns.iter().filter(|p| self.bytecode.windows(p.len()).any(|w| w == *p)).count();
            
            return dex_count >= 2;
        }
        
        false
    }

    fn has_incentive_manipulation(&self) -> bool {
        let incentive_patterns = [b"reward", b"stake", b"claim", b"bonus"];
        let has_incentives = incentive_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_incentives {
            let loop_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
            return loop_count > 3;
        }
        
        false
    }

    fn has_pool_draining_pattern(&self) -> bool {
        let drain_patterns = [b"withdraw", b"remove", b"burn"];
        let has_drain = drain_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_drain {
            let call_count = self.bytecode.iter().filter(|&&b| b == 0xf1 || b == 0xfa).count();
            let has_slippage = self.bytecode.windows(8).any(|w| w == b"slippage" || w == b"minOut");
            
            return call_count > 4 && !has_slippage;
        }
        
        false
    }
}
