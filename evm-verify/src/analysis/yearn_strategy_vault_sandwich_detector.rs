pub struct YearnStrategyVaultSandwichDetector {
    bytecode: Vec<u8>,
}

impl YearnStrategyVaultSandwichDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_harvest_frontrunning() {
            findings.push("Yearn vault: Harvest operation vulnerable to frontrunning".to_string());
        }

        if self.has_deposit_withdrawal_sandwich() {
            findings.push("Yearn vault: Deposit/withdrawal sandwich attack possible".to_string());
        }

        if self.has_strategy_migration_exploit() {
            findings.push("Yearn vault: Strategy migration vulnerable to exploitation".to_string());
        }

        findings
    }

    fn has_harvest_frontrunning(&self) -> bool {
        let harvest_patterns = [b"harvest", b"Harvest", b"earn"];
        let has_harvest = harvest_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_harvest {
            let slippage_patterns = [b"slippage", b"minOut", b"deadline"];
            let has_protection = slippage_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_protection;
        }
        
        false
    }

    fn has_deposit_withdrawal_sandwich(&self) -> bool {
        let vault_ops = [b"deposit", b"withdraw", b"shares"];
        let has_vault_ops = vault_ops.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_vault_ops {
            let call_count = self.bytecode.iter().filter(|&&b| b == 0xf1 || b == 0xfa).count();
            return call_count > 3;
        }
        
        false
    }

    fn has_strategy_migration_exploit(&self) -> bool {
        let migration_patterns = [b"migrate", b"setStrategy", b"updateStrategy"];
        let has_migration = migration_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_migration {
            let timelock_patterns = [b"timelock", b"delay", b"queue"];
            let has_timelock = timelock_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_timelock;
        }
        
        false
    }
}
