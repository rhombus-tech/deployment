pub struct TranchedVaultSeniorityViolationDetector {
    bytecode: Vec<u8>,
}

impl TranchedVaultSeniorityViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_seniority_ordering_violation() {
            findings.push("Tranched vault: Seniority ordering can be violated".to_string());
        }

        if self.has_waterfall_distribution_bypass() {
            findings.push("Tranched vault: Waterfall distribution can be bypassed".to_string());
        }

        if self.has_junior_tranche_priority_manipulation() {
            findings.push("Tranched vault: Junior tranche can manipulate priority".to_string());
        }

        findings
    }

    fn has_seniority_ordering_violation(&self) -> bool {
        let tranche_patterns = [b"tranche", b"Tranche", b"senior", b"junior"];
        let has_tranche = tranche_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_tranche {
            let withdraw_patterns = [b"withdraw", b"redeem", b"claim"];
            let has_withdraw = withdraw_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_withdraw {
                let order_patterns = [b"priority", b"order", b"seniority"];
                let has_order = order_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_order;
            }
        }
        
        false
    }

    fn has_waterfall_distribution_bypass(&self) -> bool {
        let distribution_patterns = [b"distribute", b"payout", b"allocate"];
        let has_distribution = distribution_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_distribution {
            let waterfall_patterns = [b"waterfall", b"cascade", b"sequential"];
            let has_waterfall = waterfall_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if !has_waterfall {
                let tranche_patterns = [b"tranche", b"senior", b"junior"];
                let has_tranche = tranche_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return has_tranche;
            }
        }
        
        false
    }

    fn has_junior_tranche_priority_manipulation(&self) -> bool {
        let junior_patterns = [b"junior", b"Junior", b"equity"];
        let has_junior = junior_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_junior {
            let claim_patterns = [b"claim", b"withdraw", b"redeem"];
            let has_claim = claim_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_claim {
                let lock_patterns = [b"locked", b"frozen", b"restricted"];
                let has_lock = lock_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_lock;
            }
        }
        
        false
    }
}
