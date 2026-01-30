use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityReputationGamingVulnerability {
    pub location: usize,
    pub gaming_type: ReputationGamingType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReputationGamingType {
    SybilReputationFarming,          // Create multiple entities to farm reputation
    FailureHiding,                   // Hide failures to maintain reputation
    ThrottlingBypass,                // Bypass throttling via reputation manipulation
    StakeManipulation,               // Manipulate stake to game reputation
    SelectiveReporting,              // Report only successes, hide failures
    CrossEntityReputation,           // Share reputation across entities
}

pub struct EntityReputationGamingDetector {
    bytecode: Vec<u8>,
}

impl EntityReputationGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EntityReputationGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_sybil_reputation_farming() {
            vulnerabilities.push(EntityReputationGamingVulnerability {
                location: loc,
                gaming_type: ReputationGamingType::SybilReputationFarming,
                severity: "Critical".to_string(),
                description: "Bundler can create multiple entity identities to farm reputation scores. \
                             No proper sybil resistance mechanism. Attacker can maintain high reputation \
                             across entities while executing attacks.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_failure_hiding() {
            vulnerabilities.push(EntityReputationGamingVulnerability {
                location: loc,
                gaming_type: ReputationGamingType::FailureHiding,
                severity: "High".to_string(),
                description: "Entity can hide UserOp failures from reputation system. Failed operations \
                             not properly reported, allowing entity to maintain artificially high \
                             reputation score.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_throttling_bypass() {
            vulnerabilities.push(EntityReputationGamingVulnerability {
                location: loc,
                gaming_type: ReputationGamingType::ThrottlingBypass,
                severity: "High".to_string(),
                description: "High reputation allows bypassing per-entity throttling limits. Entity can \
                             game reputation to avoid rate limits and spam network.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_stake_manipulation() {
            vulnerabilities.push(EntityReputationGamingVulnerability {
                location: loc,
                gaming_type: ReputationGamingType::StakeManipulation,
                severity: "Critical".to_string(),
                description: "Entity can manipulate stake amounts to game reputation system. Temporary \
                             stake increases to pass checks, then withdraw to avoid slashing.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_selective_reporting() {
            vulnerabilities.push(EntityReputationGamingVulnerability {
                location: loc,
                gaming_type: ReputationGamingType::SelectiveReporting,
                severity: "Medium".to_string(),
                description: "Entity reports only successful operations while hiding failures. Reputation \
                             system receives biased data, inflating entity's score.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_cross_entity_reputation() {
            vulnerabilities.push(EntityReputationGamingVulnerability {
                location: loc,
                gaming_type: ReputationGamingType::CrossEntityReputation,
                severity: "High".to_string(),
                description: "Multiple entities share reputation score, allowing one entity to benefit \
                             from another's good standing. Enables reputation laundering.".to_string(),
                confidence: 0.87,
            });
        }

        vulnerabilities
    }

    fn detect_sybil_reputation_farming(&self) -> Option<usize> {
        // Multiple entity creation without proper identity binding
        // Pattern: CREATE or CREATE2 without proper stake/identity validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xf0 || self.bytecode[i] == 0xf5 { // CREATE or CREATE2
                // Check for stake validation within next 15 instructions
                let mut has_stake_check = false;
                for j in i..std::cmp::min(i + 15, self.bytecode.len()) {
                    // Look for BALANCE check or SLOAD (stake storage)
                    if self.bytecode[j] == 0x31 || self.bytecode[j] == 0x54 {
                        has_stake_check = true;
                        break;
                    }
                }
                if !has_stake_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_failure_hiding(&self) -> Option<usize> {
        // UserOp execution without proper failure reporting
        // Pattern: CALL without checking return value or emitting failure event
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0xf1 { // CALL
                // Check if return value is checked
                if i + 2 < self.bytecode.len() {
                    let has_return_check = self.bytecode[i + 1] == 0x15 || // ISZERO
                                          self.bytecode[i + 1] == 0x50;     // POP (ignoring result)
                    
                    // Check for LOG (event emission)
                    let mut has_event = false;
                    for j in i..std::cmp::min(i + 12, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0xa0..=0xa4) { // LOG0-LOG4
                            has_event = true;
                            break;
                        }
                    }
                    
                    if !has_return_check && !has_event {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_throttling_bypass(&self) -> Option<usize> {
        // Reputation check without proper throttling enforcement
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for reputation score load
            if self.bytecode[i] == 0x54 { // SLOAD (reputation score)
                // Check if followed by throttling check
                let mut has_throttle = false;
                for j in i + 1..std::cmp::min(i + 20, self.bytecode.len()) {
                    // Look for time-based or count-based comparison
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        if j + 3 < self.bytecode.len() && 
                           matches!(self.bytecode[j + 2], 0x10 | 0x11) { // LT or GT
                            has_throttle = true;
                            break;
                        }
                    }
                }
                if !has_throttle {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_stake_manipulation(&self) -> Option<usize> {
        // Stake deposit/withdrawal without proper lock period
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                // Common stake selectors: unstakeDeposit (0xbb9fe6bf), withdrawStake (0xc23a5cea)
                if selector == 0xbb9fe6bf || selector == 0xc23a5cea {
                    // Check for delay validation
                    let mut has_delay_check = false;
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            has_delay_check = true;
                            break;
                        }
                    }
                    if !has_delay_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_selective_reporting(&self) -> Option<usize> {
        // Event emission only on success path
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x15 { // ISZERO (checking call success)
                // Check if only success path has LOG
                let mut success_has_log = false;
                let mut failure_has_log = false;
                
                for j in i + 1..std::cmp::min(i + 15, self.bytecode.len()) {
                    if self.bytecode[j] == 0x57 { // JUMPI (conditional jump)
                        // Check success branch
                        for k in j + 1..std::cmp::min(j + 10, self.bytecode.len()) {
                            if matches!(self.bytecode[k], 0xa0..=0xa4) {
                                success_has_log = true;
                                break;
                            }
                        }
                        break;
                    }
                }
                
                if success_has_log && !failure_has_log {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_cross_entity_reputation(&self) -> Option<usize> {
        // Reputation score shared across addresses
        // Pattern: Reputation SLOAD using non-sender address
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD (external address)
                for j in i + 1..std::cmp::min(i + 12, self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // SLOAD (reputation lookup)
                        // Check if using caller vs external address
                        let mut uses_caller = false;
                        for k in i..j {
                            if self.bytecode[k] == 0x33 { // CALLER
                                uses_caller = true;
                                break;
                            }
                        }
                        if !uses_caller {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
