use crate::bytecode::SecurityFinding;

pub struct DynamicNftStateManipulationDetector {
    bytecode: Vec<u8>,
}

impl DynamicNftStateManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_unprotected_state_change() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Dynamic NFT state can be modified without proper authorization at PC {}. \
                    NFT attributes or evolution state can be manipulated by unauthorized parties.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_evolution_oracle_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "NFT evolution conditions rely on manipulable oracle at PC {}. \
                    Evolution triggers can be gamed through oracle manipulation.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_reveal_mechanism_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "NFT reveal mechanism vulnerable to front-running or manipulation at PC {}. \
                    Reveal timing or randomness can be exploited.",
                    pc
                ),
                pc,
                confidence: 0.86,
            });
        }

        findings
    }

    fn detect_unprotected_state_change(&self) -> Option<usize> {
        // Look for state change functions without proper access control
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // updateState, evolve, levelUp, changeAttribute selectors
                if matches!(selector, [0x5d, 0x3a, _, _] | [0x6f, 0x4b, _, _] | [0x7e, 0x8c, _, _] | [0x8f, 0x9d, _, _]) {
                    let mut has_owner_check = false;
                    let mut has_authorized_controller = false;
                    let mut modifies_state = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for owner verification
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 { // SLOAD
                                // Check for owner comparison
                                for k in j..j + 5 {
                                    if self.bytecode[k] == 0x33 && // CALLER
                                       k + 1 < self.bytecode.len() && self.bytecode[k + 1] == 0x14 { // EQ
                                        has_owner_check = true;
                                    }
                                }
                            }
                        }
                        // Check for authorized controller role
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // hasRole, isController selectors
                            if matches!(sub_selector, [0x91, 0xd1, 0x48, 0x54] | [0xa2, 0x3f, _, _]) {
                                has_authorized_controller = true;
                            }
                        }
                        if self.bytecode[j] == 0x55 { // SSTORE (modifying state)
                            modifies_state = true;
                        }
                    }
                    
                    if modifies_state && !has_owner_check && !has_authorized_controller {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_evolution_oracle_manipulation(&self) -> Option<usize> {
        // Look for evolution triggers relying on single oracle
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // canEvolve, checkEvolutionCondition, triggerEvolution selectors
                if matches!(selector, [0x7a, 0x4e, _, _] | [0x8b, 0x5f, _, _] | [0x9c, 0x7d, _, _]) {
                    let mut has_single_oracle = false;
                    let mut has_multiple_sources = false;
                    let mut has_onchain_validation = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for external oracle call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // getOracleData, fetchCondition selectors
                            if matches!(sub_selector, [0xa1, 0x2f, _, _] | [0xb3, 0x4d, _, _]) {
                                has_single_oracle = true;
                            }
                        }
                        // Check for multiple oracle calls (redundancy)
                        if j + 30 < self.bytecode.len() {
                            let mut call_count = 0;
                            for k in j..j + 30 {
                                if self.bytecode[k] == 0xfa || self.bytecode[k] == 0xf1 { // STATICCALL or CALL
                                    call_count += 1;
                                }
                            }
                            if call_count >= 2 {
                                has_multiple_sources = true;
                            }
                        }
                        // Check for onchain condition validation (state checks)
                        if j + 8 < self.bytecode.len() {
                            let mut has_comparison = false;
                            let mut has_state_load = false;
                            for k in j..j + 8 {
                                if self.bytecode[k] == 0x54 { // SLOAD
                                    has_state_load = true;
                                }
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                    has_comparison = true;
                                }
                            }
                            if has_state_load && has_comparison {
                                has_onchain_validation = true;
                            }
                        }
                    }
                    
                    if has_single_oracle && !has_multiple_sources && !has_onchain_validation {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_reveal_mechanism_exploit(&self) -> Option<usize> {
        // Look for reveal functions with weak randomness or timing issues
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // reveal, unveil, showMetadata selectors
                if matches!(selector, [0x6a, 0x4b, _, _] | [0x7c, 0x5d, _, _] | [0x8e, 0x6f, _, _]) {
                    let mut uses_weak_randomness = false;
                    let mut missing_commit_reveal = false;
                    let mut vulnerable_timing = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for weak randomness (TIMESTAMP or BLOCKHASH alone)
                        if j + 3 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 || // TIMESTAMP
                               self.bytecode[j] == 0x40 { // BLOCKHASH
                                // Check if used directly for randomness (KECCAK256)
                                if j + 2 < self.bytecode.len() && self.bytecode[j + 2] == 0x20 {
                                    uses_weak_randomness = true;
                                }
                            }
                        }
                        // Check for commit-reveal pattern (two-phase reveal)
                        let mut has_commit_storage = false;
                        let mut has_reveal_verification = false;
                        if j + 10 < self.bytecode.len() {
                            for k in j..j + 10 {
                                if self.bytecode[k] == 0x54 { // SLOAD (loading commitment)
                                    has_commit_storage = true;
                                }
                                if self.bytecode[k] == 0x14 { // EQ (verifying commitment)
                                    has_reveal_verification = true;
                                }
                            }
                        }
                        if !has_commit_storage || !has_reveal_verification {
                            missing_commit_reveal = true;
                        }
                        // Check for immediate reveal after mint (no delay)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 { // SLOAD (mint time)
                                // Check if no delay enforced
                                let mut has_delay = false;
                                for k in j..j + 6 {
                                    if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                        has_delay = true;
                                    }
                                }
                                if !has_delay {
                                    vulnerable_timing = true;
                                }
                            }
                        }
                    }
                    
                    if uses_weak_randomness || missing_commit_reveal || vulnerable_timing {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
