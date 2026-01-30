pub struct GovernanceTokenVoteBuyingDetector {
    bytecode: Vec<u8>,
}

impl GovernanceTokenVoteBuyingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_unprotected_vote_delegation() {
            findings.push("Governance: Vote delegation vulnerable to buying attacks".to_string());
        }

        if self.has_flashloan_governance_manipulation() {
            findings.push("Governance: Flash loan can manipulate voting power".to_string());
        }

        if self.has_missing_vote_lock_mechanism() {
            findings.push("Governance: Missing vote-locking prevents commitment".to_string());
        }

        findings
    }

    fn has_unprotected_vote_delegation(&self) -> bool {
        let delegate_patterns = [b"delegate", b"Delegate", b"delegateBySig"];
        let has_delegate = delegate_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_delegate {
            let vote_patterns = [b"vote", b"Vote", b"voting"];
            let has_vote = vote_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_vote {
                let protection_patterns = [b"lockup", b"vesting", b"cooldown"];
                let has_protection = protection_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_protection;
            }
        }
        
        false
    }

    fn has_flashloan_governance_manipulation(&self) -> bool {
        let governance_patterns = [b"propose", b"vote", b"execute"];
        let has_governance = governance_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_governance {
            let token_patterns = [b"balanceOf", b"transfer", b"transferFrom"];
            let has_token = token_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_token {
                let snapshot_patterns = [b"snapshot", b"checkpoint", b"getPriorVotes"];
                let has_snapshot = snapshot_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_snapshot;
            }
        }
        
        false
    }

    fn has_missing_vote_lock_mechanism(&self) -> bool {
        let voting_patterns = [b"castVote", b"vote", b"submitVote"];
        let has_voting = voting_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_voting {
            let has_timestamp = self.bytecode.iter().any(|&b| b == 0x42);
            
            if has_timestamp {
                let lock_patterns = [b"locked", b"lockedUntil", b"lockDuration"];
                let has_lock = lock_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_lock;
            }
        }
        
        false
    }
}
