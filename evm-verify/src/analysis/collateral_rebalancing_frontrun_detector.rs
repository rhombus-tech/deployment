pub struct CollateralRebalancingFrontrunDetector {
    bytecode: Vec<u8>,
}

impl CollateralRebalancingFrontrunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_predictable_rebalancing() {
            findings.push("Collateral: Rebalancing logic is predictable and frontrunnable".to_string());
        }

        if self.has_no_rebalancing_delay() {
            findings.push("Collateral: No delay mechanism on rebalancing operations".to_string());
        }

        if self.has_oracle_price_frontrun_risk() {
            findings.push("Collateral: Oracle price updates can be front-run during rebalancing".to_string());
        }

        findings
    }

    fn has_predictable_rebalancing(&self) -> bool {
        let rebalance_patterns = [b"rebalance", b"Rebalance", b"adjust"];
        let has_rebalance = rebalance_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_rebalance {
            let collateral_patterns = [b"collateral", b"Collateral", b"asset"];
            let has_collateral = collateral_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_collateral {
                let random_patterns = [b"random", b"entropy", b"unpredictable"];
                let has_random = random_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_random;
            }
        }
        
        false
    }

    fn has_no_rebalancing_delay(&self) -> bool {
        let rebalance_patterns = [b"rebalance", b"adjust", b"reallocate"];
        let has_rebalance = rebalance_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_rebalance {
            let has_timestamp = self.bytecode.iter().any(|&b| b == 0x42);
            
            if has_timestamp {
                let delay_patterns = [b"delay", b"cooldown", b"minInterval"];
                let has_delay = delay_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_delay;
            }
        }
        
        false
    }

    fn has_oracle_price_frontrun_risk(&self) -> bool {
        let oracle_patterns = [b"oracle", b"Oracle", b"getPrice"];
        let has_oracle = oracle_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_oracle {
            let rebalance_patterns = [b"rebalance", b"swap", b"trade"];
            let has_rebalance = rebalance_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_rebalance {
                let commit_patterns = [b"commit", b"reveal", b"twap"];
                let has_commit = commit_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_commit;
            }
        }
        
        false
    }
}
