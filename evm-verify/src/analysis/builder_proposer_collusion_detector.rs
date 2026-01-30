use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuilderProposerCollusionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct BuilderProposerCollusionDetector {
    bytecode: Vec<u8>,
}

impl BuilderProposerCollusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BuilderProposerCollusionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // PBS (Proposer-Builder Separation) enables builder-proposer collusion
        // Detect block builder preferential treatment
        if let Some(location) = self.has_builder_preferential_treatment() {
            vulnerabilities.push(BuilderProposerCollusionVulnerability {
                vulnerability_type: "Builder-Proposer Collusion Risk".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Protocol allows block builder to provide preferential treatment to specific addresses. Colluding builder-proposer pairs can extract MEV by front-running or censoring transactions. Implement equal access guarantees or encrypted mempools.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect proposer payment dependency on outcomes
        if let Some(location) = self.has_outcome_dependent_proposer_payment() {
            vulnerabilities.push(BuilderProposerCollusionVulnerability {
                vulnerability_type: "Outcome-Dependent Proposer Payment".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Proposer payment varies based on transaction outcomes within block. Incentivizes proposers to collude with builders for manipulation. Use fixed proposer payments independent of transaction results.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect unbounded builder payments creating collusion incentive
        if let Some(location) = self.has_unbounded_builder_payment() {
            vulnerabilities.push(BuilderProposerCollusionVulnerability {
                vulnerability_type: "Unbounded Builder Payment Collusion".to_string(),
                location,
                severity: "High".to_string(),
                description: "Builder can pay unlimited amount to proposer for block inclusion. Creates incentive for proposers to accept malicious blocks. Implement maximum builder payment caps.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_builder_preferential_treatment(&self) -> Option<usize> {
        // Pattern: Address-based preferential execution (whitelisting builders)
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for address comparison
            if self.bytecode[i] == 0x33 { // CALLER
                // Check if used for preferential logic
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 { // EQ (checking if specific builder)
                        // Check if grants special privileges (different gas, front-run, etc.)
                        for k in j+1..(j+25).min(self.bytecode.len()).min(self.bytecode.len()) {
                            // Look for conditional execution path
                            if self.bytecode[k] == 0x57 { // JUMPI (conditional branch)
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_outcome_dependent_proposer_payment(&self) -> Option<usize> {
        // Pattern: Proposer payment calculated from transaction results
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for payment transfer to proposer (COINBASE)
            if self.bytecode[i] == 0x41 { // COINBASE (proposer address)
                // Check if payment amount depends on state changes
                for j in i+1..i+35.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xf1 { // CALL (payment transfer)
                        // Check if amount calculated from state (SLOAD)
                        let mut amount_from_state = false;
                        
                        for k in j.saturating_sub(25)..j {
                            if self.bytecode[k] == 0x54 { // SLOAD (reading outcome)
                                // Check if used in calculation
                                for m in k+1..j {
                                    if self.bytecode[m] == 0x02 || self.bytecode[m] == 0x04 { // MUL or DIV
                                        amount_from_state = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if amount_from_state {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_unbounded_builder_payment(&self) -> Option<usize> {
        // Pattern: Builder payment to proposer without caps
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for payment to COINBASE (proposer)
            if self.bytecode[i] == 0x41 { // COINBASE
                for j in i+1..i+30.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xf1 { // CALL (payment)
                        // Check if payment amount has upper bound
                        let mut has_cap = false;
                        
                        for k in j.saturating_sub(30)..j {
                            // Look for maximum check
                            if self.bytecode[k] == 0x10 { // LT (amount < max)
                                has_cap = true;
                            }
                            // Or MIN operation
                            if self.bytecode[k] == 0x1b { // SHL (bit manipulation for min)
                                has_cap = true;
                            }
                        }
                        
                        if !has_cap {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
