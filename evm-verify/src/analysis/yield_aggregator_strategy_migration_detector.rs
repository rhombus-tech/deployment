pub struct YieldAggregatorStrategyMigrationDetector {
    bytecode: Vec<u8>,
}

impl YieldAggregatorStrategyMigrationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_unprotected_strategy_migration() {
            findings.push("Yield aggregator: Strategy migration lacks protection".to_string());
        }

        if self.has_slippage_during_migration() {
            findings.push("Yield aggregator: Migration vulnerable to slippage attacks".to_string());
        }

        if self.has_funds_at_risk_during_transition() {
            findings.push("Yield aggregator: Funds exposed during strategy transition".to_string());
        }

        findings
    }

    fn has_unprotected_strategy_migration(&self) -> bool {
        let migrate_patterns = [b"migrate", b"Migration", b"setStrategy"];
        let has_migrate = migrate_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_migrate {
            let strategy_patterns = [b"strategy", b"Strategy"];
            let has_strategy = strategy_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_strategy {
                let timelock_patterns = [b"timelock", b"delay", b"queue"];
                let has_timelock = timelock_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_timelock;
            }
        }
        
        false
    }

    fn has_slippage_during_migration(&self) -> bool {
        let withdrawal_patterns = [b"withdraw", b"Withdraw", b"redeem"];
        let has_withdrawal = withdrawal_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_withdrawal {
            let deposit_patterns = [b"deposit", b"Deposit", b"mint"];
            let has_deposit = deposit_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_deposit {
                let slippage_patterns = [b"slippage", b"minAmount", b"minOut"];
                let has_slippage = slippage_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_slippage;
            }
        }
        
        false
    }

    fn has_funds_at_risk_during_transition(&self) -> bool {
        let vault_patterns = [b"vault", b"Vault", b"totalAssets"];
        let has_vault = vault_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_vault {
            let has_call = self.bytecode.iter().any(|&b| b == 0xF1);
            
            if has_call {
                let emergency_patterns = [b"pause", b"emergency", b"guardian"];
                let has_emergency = emergency_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_emergency;
            }
        }
        
        false
    }
}
