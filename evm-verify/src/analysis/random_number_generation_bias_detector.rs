// Random Number Generation Bias Detector
// Detects VRF gaming edge cases and RNG predictability vulnerabilities

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomNumberGenerationBiasVulnerability {
    pub location: usize,
    pub vulnerability_type: RNGBiasType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RNGBiasType {
    VRFGamingEdgeCases,              // VRF result manipulation edge cases
    BlockHashPredictability,         // Predictable blockhash randomness
    ModuloBiasExploitation,          // Modulo operation introduces bias
    CommitRevealRaceCondition,       // Commit-reveal timing attack
    RandomnessSeedManipulation,      // Seed value controllable
    InsufficientEntropySource,       // Weak entropy for randomness
}

pub struct RandomNumberGenerationBiasDetector {
    bytecode: Vec<u8>,
}

impl RandomNumberGenerationBiasDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RandomNumberGenerationBiasVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_vrf_gaming_edge_cases() {
            vulnerabilities.push(RandomNumberGenerationBiasVulnerability {
                location: loc,
                vulnerability_type: RNGBiasType::VRFGamingEdgeCases,
                severity: SecuritySeverity::High,
                description: "VRF output edge cases not handled. Extreme values or special cases \
                             in VRF result allow gaming through selective participation.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_blockhash_predictability() {
            vulnerabilities.push(RandomNumberGenerationBiasVulnerability {
                location: loc,
                vulnerability_type: RNGBiasType::BlockHashPredictability,
                severity: SecuritySeverity::Critical,
                description: "Blockhash used for randomness without delay. Miners can manipulate \
                             blockhash by withholding blocks when outcome is unfavorable.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_modulo_bias_exploitation() {
            vulnerabilities.push(RandomNumberGenerationBiasVulnerability {
                location: loc,
                vulnerability_type: RNGBiasType::ModuloBiasExploitation,
                severity: SecuritySeverity::High,
                description: "Modulo operation on random value introduces bias. Non-uniform \
                             distribution favors lower values enabling statistical attacks.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_commit_reveal_race_condition() {
            vulnerabilities.push(RandomNumberGenerationBiasVulnerability {
                location: loc,
                vulnerability_type: RNGBiasType::CommitRevealRaceCondition,
                severity: SecuritySeverity::High,
                description: "Commit-reveal timing exploitable. Late revealer sees others' commitments \
                             and can selectively participate or abort.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_randomness_seed_manipulation() {
            vulnerabilities.push(RandomNumberGenerationBiasVulnerability {
                location: loc,
                vulnerability_type: RNGBiasType::RandomnessSeedManipulation,
                severity: SecuritySeverity::Critical,
                description: "Randomness seed partially controllable by participants. Seed construction \
                             allows influence through strategic input contribution.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_insufficient_entropy_source() {
            vulnerabilities.push(RandomNumberGenerationBiasVulnerability {
                location: loc,
                vulnerability_type: RNGBiasType::InsufficientEntropySource,
                severity: SecuritySeverity::Critical,
                description: "Entropy source has insufficient randomness. Limited entropy allows \
                             brute force prediction of random outcomes.".to_string(),
                confidence: 0.89,
            });
        }

        vulnerabilities
    }

    fn detect_vrf_gaming_edge_cases(&self) -> Option<usize> {
        // Pattern: VRF result used without range validation
        // External call result used directly without bounds check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (VRF query)
                let mut used_for_randomness = false;
                let mut validates_range = false;
                
                // Check if result used for random selection
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 {  // MOD (random selection)
                        used_for_randomness = true;
                    }
                }
                
                // Check for edge case handling (min/max bounds)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT (bounds)
                        validates_range = true;
                    }
                }
                
                if used_for_randomness && !validates_range {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_blockhash_predictability(&self) -> Option<usize> {
        // Pattern: BLOCKHASH used without sufficient delay
        // Current or recent block hash used for randomness
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x40 {  // BLOCKHASH
                let mut used_for_random = false;
                let mut has_delay = false;
                
                // Check if used for randomness (MOD operation)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 {  // MOD (random from hash)
                        used_for_random = true;
                    }
                }
                
                // Check for delay (block number - N where N > 1)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x43 {  // NUMBER (current block)
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (historical block)
                                // Check if subtracting enough blocks (> 1)
                                for m in (k.saturating_sub(5))..k {
                                    if self.bytecode[m] == 0x60 && m+1 < self.bytecode.len() {
                                        if self.bytecode[m+1] > 1 {  // At least 2 blocks
                                            has_delay = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                if used_for_random && !has_delay {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_modulo_bias_exploitation(&self) -> Option<usize> {
        // Pattern: Modulo on random value without bias mitigation
        // Direct MOD without rejection sampling
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x06 {  // MOD (random % range)
                let mut is_random_source = false;
                let mut has_bias_mitigation = false;
                
                // Check if input is from randomness source
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x40 || self.bytecode[j] == 0xFA {  // BLOCKHASH or CALL
                        is_random_source = true;
                    }
                }
                
                // Check for bias mitigation (rejection sampling loop)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Rejection: if result >= (2^256 / range) * range, retry
                    if self.bytecode[j] == 0x10 {  // LT (rejection check)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x57 {  // JUMPI (retry on reject)
                                has_bias_mitigation = true;
                            }
                        }
                    }
                }
                
                if is_random_source && !has_bias_mitigation {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_commit_reveal_race_condition(&self) -> Option<usize> {
        // Pattern: Reveal phase without timing enforcement
        // Can delay reveal to see others' commitments
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (reveal)
                let mut is_reveal = false;
                let mut has_deadline = false;
                
                // Check if reveal operation (unhashing commitment)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x20 {  // SHA3 (verify commitment hash)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (match commitment)
                                is_reveal = true;
                            }
                        }
                    }
                }
                
                // Check for reveal deadline enforcement
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (before deadline)
                                has_deadline = true;
                            }
                        }
                    }
                }
                
                if is_reveal && !has_deadline {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_randomness_seed_manipulation(&self) -> Option<usize> {
        // Pattern: Seed derived from user-controllable inputs
        // User input directly affects seed without sufficient mixing
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x20 {  // SHA3 (generate seed)
                let mut has_user_input = false;
                let mut has_secure_mixing = false;
                
                // Check if user input in seed
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x33 || self.bytecode[j] == 0x35 {  // CALLER or CALLDATALOAD
                        has_user_input = true;
                    }
                }
                
                // Check for secure mixing (block hash + multiple participants)
                let mut mixing_sources = 0;
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x40 {  // BLOCKHASH (entropy source)
                        mixing_sources += 1;
                    }
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP (entropy source)
                        mixing_sources += 1;
                    }
                }
                
                has_secure_mixing = mixing_sources >= 2;
                
                if has_user_input && !has_secure_mixing {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_insufficient_entropy_source(&self) -> Option<usize> {
        // Pattern: Single weak entropy source for randomness
        // Only one source without combination of multiple
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x06 {  // MOD (final random value)
                let mut entropy_sources = 0;
                
                // Count entropy sources in preceding operations
                for j in (i.saturating_sub(30))..i {
                    if self.bytecode[j] == 0x40 {  // BLOCKHASH
                        entropy_sources += 1;
                    }
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        entropy_sources += 1;
                    }
                    if self.bytecode[j] == 0xFA {  // STATICCALL (VRF/oracle)
                        entropy_sources += 1;
                    }
                    if self.bytecode[j] == 0x54 {  // SLOAD (stored randomness)
                        entropy_sources += 1;
                    }
                }
                
                // Need at least 2 independent entropy sources
                if entropy_sources < 2 {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: crate::bytecode::security::SecurityWarningKind::Other(
                    format!("RandomNumberGenerationBias{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Random Number Generation Bias {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Use VRF with edge case handling, delay blockhash usage, implement \
                             rejection sampling for modulo bias elimination, enforce commit-reveal \
                             deadlines, combine multiple independent entropy sources, and prevent \
                             user input from directly controlling randomness seeds".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockhash_predictability() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x40, // BLOCKHASH (current block)
            0x60, 0x0A, // PUSH1 10
            0x06, // MOD (random without delay)
        ];
        
        let detector = RandomNumberGenerationBiasDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, RNGBiasType::BlockHashPredictability)));
    }

    #[test]
    fn test_modulo_bias_exploitation() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x40, // BLOCKHASH
            0x60, 0x64, // PUSH1 100
            0x06, // MOD (direct modulo without rejection sampling)
        ];
        
        let detector = RandomNumberGenerationBiasDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, RNGBiasType::ModuloBiasExploitation)));
    }
}
