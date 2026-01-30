use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingParameterManipulationVulnerability {
    pub location: usize,
    pub manipulation_type: SlashingManipulationType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingManipulationType {
    ArbitrarySlashingThreshold,      // Slash threshold can be set arbitrarily
    SlashingWithoutAppeal,           // No appeal mechanism for slashing
    UnboundedSlashingAmount,         // Slash amount not capped
    TimeManipulationSlashing,        // Manipulate time to trigger slashing
    SelectiveSlashingEnforcement,    // Slash some participants but not others
    SlashingRewardManipulation,      // Manipulate rewards from slashing
}

pub struct SlashingParameterManipulationDetector {
    bytecode: Vec<u8>,
}

impl SlashingParameterManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SlashingParameterManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_arbitrary_slashing_threshold() {
            vulnerabilities.push(SlashingParameterManipulationVulnerability {
                location: loc,
                manipulation_type: SlashingManipulationType::ArbitrarySlashingThreshold,
                severity: "Critical".to_string(),
                description: "Slashing threshold parameters can be set to arbitrary values without bounds. \
                             Allows admin to slash honest participants by lowering threshold or protect \
                             malicious actors by raising it.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_slashing_without_appeal() {
            vulnerabilities.push(SlashingParameterManipulationVulnerability {
                location: loc,
                manipulation_type: SlashingManipulationType::SlashingWithoutAppeal,
                severity: "High".to_string(),
                description: "Slashing mechanism lacks appeal or dispute resolution process. Once slashed, \
                             no mechanism exists to challenge or reverse potentially incorrect slashing.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_unbounded_slashing_amount() {
            vulnerabilities.push(SlashingParameterManipulationVulnerability {
                location: loc,
                manipulation_type: SlashingManipulationType::UnboundedSlashingAmount,
                severity: "Critical".to_string(),
                description: "Slashing amount has no maximum cap. Allows complete confiscation of stake \
                             for minor violations or manipulation to extract maximum value.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_time_manipulation_slashing() {
            vulnerabilities.push(SlashingParameterManipulationVulnerability {
                location: loc,
                manipulation_type: SlashingManipulationType::TimeManipulationSlashing,
                severity: "High".to_string(),
                description: "Slashing conditions depend on timestamp that can be manipulated. Validators \
                             can be slashed by manipulating block timestamps or deadlines.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_selective_slashing() {
            vulnerabilities.push(SlashingParameterManipulationVulnerability {
                location: loc,
                manipulation_type: SlashingManipulationType::SelectiveSlashingEnforcement,
                severity: "High".to_string(),
                description: "Slashing can be selectively enforced or bypassed for specific participants. \
                             Allows privileged actors to avoid slashing while others are penalized.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_slashing_reward_manipulation() {
            vulnerabilities.push(SlashingParameterManipulationVulnerability {
                location: loc,
                manipulation_type: SlashingManipulationType::SlashingRewardManipulation,
                severity: "Medium".to_string(),
                description: "Rewards from slashing (slasher bounty) can be manipulated to incentivize \
                             malicious slashing or disincentivize legitimate reporting.".to_string(),
                confidence: 0.83,
            });
        }

        vulnerabilities
    }

    fn detect_arbitrary_slashing_threshold(&self) -> Option<usize> {
        // Slashing threshold setter without bounds
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // setSlashingThreshold, setSlashCondition: common patterns
                if selector == 0x8a35acfb || selector == 0x7b0472f0 {
                    // Check for maximum/minimum bounds
                    let mut has_bounds = false;
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                            has_bounds = true;
                            break;
                        }
                    }
                    if !has_bounds {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_slashing_without_appeal(&self) -> Option<usize> {
        // Slash function without dispute period or appeal mechanism
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // slash selector: 0x2da25de3, slashValidator: 0x301a5880
                if selector == 0x2da25de3 || selector == 0x301a5880 {
                    // Check for dispute/appeal mechanism (storage write for appeal period)
                    let mut has_appeal_period = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        // Look for timestamp + delay (appeal window)
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            for k in j + 1..std::cmp::min(j + 10, self.bytecode.len()) {
                                if self.bytecode[k] == 0x01 && // ADD (timestamp + delay)
                                   k + 2 < self.bytecode.len() &&
                                   self.bytecode[k + 2] == 0x55 { // SSTORE (save appeal deadline)
                                    has_appeal_period = true;
                                    break;
                                }
                            }
                        }
                        if has_appeal_period {
                            break;
                        }
                    }
                    if !has_appeal_period {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_unbounded_slashing_amount(&self) -> Option<usize> {
        // Slashing calculation without maximum cap
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for stake calculation in slashing
            if self.bytecode[i] == 0x02 { // MUL (calculating slash amount)
                // Check if this is in slashing context
                let in_slash_context = i > 50 && {
                    let mut found = false;
                    for j in i.saturating_sub(50)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            if sel == 0x2da25de3 || sel == 0x301a5880 {
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                
                if in_slash_context {
                    // Check for cap on slash amount
                    let mut has_cap = false;
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT (max check)
                            has_cap = true;
                            break;
                        }
                    }
                    if !has_cap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_time_manipulation_slashing(&self) -> Option<usize> {
        // Slashing based on timestamp without proper validation
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if used in slashing condition
                for j in i + 1..std::cmp::min(i + 30, self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11 | 0x14) { // LT, GT, EQ
                        // Check if this leads to slashing
                        for k in j..std::cmp::min(j + 20, self.bytecode.len()) {
                            if self.bytecode[k] == 0x63 && k + 4 < self.bytecode.len() {
                                let sel = u32::from_be_bytes([
                                    self.bytecode[k + 1],
                                    self.bytecode[k + 2],
                                    self.bytecode[k + 3],
                                    self.bytecode[k + 4],
                                ]);
                                // Slash selectors
                                if sel == 0x2da25de3 || sel == 0x301a5880 {
                                    // Check for timestamp manipulation protection
                                    let mut has_protection = false;
                                    for m in i..k {
                                        // Look for block.number check (more manipulation-resistant)
                                        if self.bytecode[m] == 0x43 { // NUMBER
                                            has_protection = true;
                                            break;
                                        }
                                    }
                                    if !has_protection {
                                        return Some(i);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_selective_slashing(&self) -> Option<usize> {
        // Slashing with whitelist/privilege bypass
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                if selector == 0x2da25de3 || selector == 0x301a5880 {
                    // Check for privilege/whitelist check
                    let mut has_bypass = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        // Look for CALLER check with privileged bypass
                        if self.bytecode[j] == 0x33 { // CALLER
                            for k in j + 1..std::cmp::min(j + 15, self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 { // EQ (checking if privileged)
                                    if k + 2 < self.bytecode.len() && self.bytecode[k + 1] == 0x15 { // ISZERO
                                        // Privileged bypass logic
                                        has_bypass = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if has_bypass {
                            break;
                        }
                    }
                    if has_bypass {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_slashing_reward_manipulation(&self) -> Option<usize> {
        // Slasher reward calculation without proper bounds
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for reward distribution in slashing
            if self.bytecode[i] == 0x04 { // DIV (calculating reward percentage)
                // Check if in slashing context
                let in_slash_context = i > 50 && {
                    let mut found = false;
                    for j in i.saturating_sub(50)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            if sel == 0x2da25de3 || sel == 0x301a5880 {
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                
                if in_slash_context {
                    // Check for reward bounds
                    let mut has_reward_cap = false;
                    for j in i..std::cmp::min(i + 30, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                            has_reward_cap = true;
                            break;
                        }
                    }
                    if !has_reward_cap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
