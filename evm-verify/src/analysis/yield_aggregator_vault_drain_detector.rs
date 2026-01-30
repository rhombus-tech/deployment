pub struct YieldAggregatorVaultDrainDetector {
    bytecode: Vec<u8>,
}

impl YieldAggregatorVaultDrainDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_strategy_migration_vulnerability() {
            findings.push("Yield aggregator: Strategy migration can drain vault".to_string());
        }

        if self.has_harvest_manipulation() {
            findings.push("Yield aggregator: Harvest function can be manipulated".to_string());
        }

        if self.has_share_price_manipulation() {
            findings.push("Yield aggregator: Share price can be manipulated".to_string());
        }

        findings
    }

    fn has_strategy_migration_vulnerability(&self) -> bool {
        let strategy_patterns = [b"strategy", b"Strategy", b"migrate"];
        let has_strategy = strategy_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_strategy {
            let vault_patterns = [b"vault", b"Vault", b"funds"];
            let has_vault = vault_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_vault {
                let timelock_patterns = [b"timelock", b"delay", b"governance"];
                let has_timelock = timelock_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_timelock;
            }
        }
        
        false
    }

    fn has_harvest_manipulation(&self) -> bool {
        let harvest_patterns = [b"harvest", b"Harvest", b"compound"];
        let has_harvest = harvest_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_harvest {
            let reward_patterns = [b"reward", b"yield", b"profit"];
            let has_reward = reward_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_reward {
                let protection_patterns = [b"minProfit", b"slippage", b"deadline"];
                let has_protection = protection_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_protection;
            }
        }
        
        false
    }

    fn has_share_price_manipulation(&self) -> bool {
        let share_patterns = [b"share", b"Share", b"pricePerShare"];
        let has_share = share_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_share {
            let total_patterns = [b"totalAssets", b"totalSupply", b"balance"];
            let has_total = total_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_total {
                let snapshot_patterns = [b"snapshot", b"cached", b"stored"];
                let has_snapshot = snapshot_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_snapshot;
            }
        }
        
        false
    }
}
