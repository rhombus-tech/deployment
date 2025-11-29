/// VRF and Randomness Manipulation Detector
/// Detects vulnerabilities in randomness generation that can be manipulated
/// including Chainlink VRF, blockhash, and commit-reveal schemes
///
/// Critical for: NFT mints, gaming, lotteries, random selection
/// Recent exploits: Meebits (2021), various NFT mint manipulation (2023-2024)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VRFVulnerability {
    pub vulnerability_type: VRFIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VRFIssueType {
    PredictableBlockhash,          // Using blockhash with manipulable block number
    ChainlinkVRFCallbackBypass,    // VRF callback validation missing
    WeakCommitReveal,              // Commit-reveal without proper salt/delay
    AttackerControlledSeed,        // Randomness seeded from msg.sender or block data
    InsecureRandomness,            // Using block.timestamp, block.difficulty for random
    VRFResultNotValidated,         // Chainlink VRF result not verified
    RandomnessReuse,               // Same random value reused across operations
    MinerManipulableRandom,        // Randomness that miners can influence
}

pub struct VRFRandomnessDetector {
    bytecode: Vec<u8>,
    vrf_selectors: HashSet<[u8; 4]>,
}

impl VRFRandomnessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut vrf_selectors = HashSet::new();
        
        // Chainlink VRF selectors
        vrf_selectors.insert([0x2f, 0x2f, 0xf1, 0x5d]); // requestRandomness()
        vrf_selectors.insert([0x94, 0x98, 0x56, 0x59]); // fulfillRandomness()
        vrf_selectors.insert([0x1f, 0xe5, 0x43, 0xe3]); // rawFulfillRandomness()
        vrf_selectors.insert([0x5d, 0x3b, 0x1d, 0x30]); // requestRandomWords() VRF v2
        vrf_selectors.insert([0xf2, 0xfd, 0xe3, 0x8b]); // fulfillRandomWords() VRF v2
        
        Self {
            bytecode,
            vrf_selectors,
        }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VRFVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Predictable blockhash usage
        vulnerabilities.extend(self.detect_blockhash_manipulation());

        // Pattern 2: Chainlink VRF callback validation
        vulnerabilities.extend(self.detect_vrf_callback_issues());

        // Pattern 3: Weak commit-reveal schemes
        vulnerabilities.extend(self.detect_weak_commit_reveal());

        // Pattern 4: Attacker-controlled randomness seed
        vulnerabilities.extend(self.detect_attacker_controlled_seed());

        // Pattern 5: Insecure randomness sources
        vulnerabilities.extend(self.detect_insecure_randomness());

        vulnerabilities
    }

    fn detect_blockhash_manipulation(&self) -> Vec<VRFVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Pattern: BLOCKHASH used with NUMBER or user-controlled input
            if self.bytecode[i] == 0x40 { // BLOCKHASH
                // Check if preceded by NUMBER (0x43) or SUB (allowing manipulation)
                let mut is_manipulable = false;
                
                // Look back for NUMBER - offset pattern
                for j in i.saturating_sub(5)..i {
                    if self.bytecode[j] == 0x43 { // NUMBER
                        // Check for SUB to calculate blockhash(block.number - x)
                        if j + 1 < i && self.bytecode[j + 1] == 0x03 {
                            is_manipulable = true;
                        }
                    }
                    // CALLDATALOAD means user provides block number
                    if self.bytecode[j] == 0x35 {
                        is_manipulable = true;
                    }
                }

                if is_manipulable {
                    vulnerabilities.push(VRFVulnerability {
                        vulnerability_type: VRFIssueType::PredictableBlockhash,
                        severity: SecuritySeverity::High,
                        confidence: 0.85,
                        description: "BLOCKHASH used with manipulable block number for randomness".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker predicts future blockhash\n\
                            2. Submits transaction only if favorable outcome\n\
                            3. Or withholds transaction if unfavorable\n\
                            4. Miners can manipulate blockhash via block withholding\n\n\
                            Fix: Use Chainlink VRF or commit-reveal with min delay",
                            i
                        ),
                        location: i,
                    });
                }

                // Additional check: blockhash used directly as randomness
                if i + 1 < self.bytecode.len() && self.bytecode[i + 1] == 0x06 { // MOD
                    vulnerabilities.push(VRFVulnerability {
                        vulnerability_type: VRFIssueType::MinerManipulableRandom,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.90,
                        description: "Blockhash directly used as randomness source".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Miners can influence blockhash by:\n\
                            2. - Withholding blocks with unfavorable hash\n\
                            3. - Manipulating transaction ordering\n\
                            4. - MEV extraction via block construction\n\n\
                            Impact: Predictable randomness for high-value operations\n\
                            Fix: Use Chainlink VRF for unpredictable randomness",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_vrf_callback_issues(&self) -> Vec<VRFVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if contract uses Chainlink VRF
        let has_vrf = self.has_chainlink_vrf();
        if !has_vrf {
            return vulnerabilities;
        }

        // Pattern: fulfillRandomness/fulfillRandomWords without proper validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            for selector in &self.vrf_selectors {
                if i + 4 <= self.bytecode.len() && &self.bytecode[i..i + 4] == selector {
                    // Check if there's proper msg.sender validation nearby
                    let has_sender_check = self.has_vrf_coordinator_check(i);
                    
                    if !has_sender_check {
                        vulnerabilities.push(VRFVulnerability {
                            vulnerability_type: VRFIssueType::ChainlinkVRFCallbackBypass,
                            severity: SecuritySeverity::Critical,
                            confidence: 0.80,
                            description: "Chainlink VRF callback missing msg.sender validation".to_string(),
                            exploit_scenario: format!(
                                "Exploit at position {}:\n\
                                1. Attacker calls fulfillRandomness() directly\n\
                                2. Provides arbitrary randomness value\n\
                                3. Bypasses VRF security entirely\n\
                                4. Chooses favorable outcome\n\n\
                                Fix: require(msg.sender == vrfCoordinator)",
                                i
                            ),
                            location: i,
                        });
                    }

                    // Check if randomness result is actually used
                    if !self.has_randomness_usage_after(i) {
                        vulnerabilities.push(VRFVulnerability {
                            vulnerability_type: VRFIssueType::VRFResultNotValidated,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.70,
                            description: "VRF result received but not properly validated or used".to_string(),
                            exploit_scenario: format!(
                                "Exploit at position {}:\n\
                                1. VRF result may not be checked for validity\n\
                                2. Could be zero or out of expected range\n\
                                3. Edge cases not handled properly\n\n\
                                Fix: Validate randomWords[0] != 0 and in expected range",
                                i
                            ),
                            location: i,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_weak_commit_reveal(&self) -> Vec<VRFVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Commit (KECCAK256 + SSTORE) without sufficient delay
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x20 && // KECCAK256
               i + 10 < self.bytecode.len() &&
               self.bytecode[i + 5] == 0x55 { // SSTORE (commit)
                
                // Check if there's a timestamp check for delay
                let has_time_delay = self.has_timestamp_delay_check(i);
                
                if !has_time_delay {
                    vulnerabilities.push(VRFVulnerability {
                        vulnerability_type: VRFIssueType::WeakCommitReveal,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Commit-reveal scheme without minimum delay enforcement".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker commits and reveals in same block\n\
                            2. Can calculate outcome before committing\n\
                            3. Only commits if outcome is favorable\n\
                            4. Defeats purpose of commit-reveal\n\n\
                            Fix: Enforce minimum blocks/time between commit and reveal",
                            i
                        ),
                        location: i,
                    });
                }

                // Check if salt is used in commitment
                if !self.has_salt_in_commitment(i) {
                    vulnerabilities.push(VRFVulnerability {
                        vulnerability_type: VRFIssueType::WeakCommitReveal,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "Commit-reveal without salt allowing rainbow table attacks".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker precomputes commitments for all possible values\n\
                            2. Creates rainbow table of hash(value)\n\
                            3. Can determine others' committed values\n\
                            4. Gains unfair advantage\n\n\
                            Fix: Use keccak256(abi.encodePacked(value, salt, msg.sender))",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_attacker_controlled_seed(&self) -> Vec<VRFVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Pattern: CALLER or ORIGIN used in randomness calculation
            if (self.bytecode[i] == 0x33 || self.bytecode[i] == 0x32) && // CALLER or ORIGIN
               i + 5 < self.bytecode.len() {
                
                // Check if it's used in KECCAK256 or MOD (randomness)
                for j in i..i.saturating_add(10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 || self.bytecode[j] == 0x06 { // KECCAK or MOD
                        vulnerabilities.push(VRFVulnerability {
                            vulnerability_type: VRFIssueType::AttackerControlledSeed,
                            severity: SecuritySeverity::Critical,
                            confidence: 0.85,
                            description: "Randomness seeded with attacker-controllable value (msg.sender/tx.origin)".to_string(),
                            exploit_scenario: format!(
                                "Exploit at position {}:\n\
                                1. Attacker can control msg.sender via contract\n\
                                2. Generates multiple addresses to find favorable seed\n\
                                3. Only interacts with address that gives desired outcome\n\
                                4. Completely predictable 'randomness'\n\n\
                                Fix: Use Chainlink VRF or blockhash with proper delay",
                                i
                            ),
                            location: i,
                        });
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_insecure_randomness(&self) -> Vec<VRFVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Pattern 1: TIMESTAMP used for randomness
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                if i + 5 < self.bytecode.len() && 
                   (self.bytecode[i + 1] == 0x06 || // MOD
                    self.bytecode[i + 1] == 0x20) { // KECCAK
                    
                    vulnerabilities.push(VRFVulnerability {
                        vulnerability_type: VRFIssueType::InsecureRandomness,
                        severity: SecuritySeverity::High,
                        confidence: 0.90,
                        description: "block.timestamp used as randomness source".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Miners control timestamp (15 sec drift)\n\
                            2. Attacker simulates outcomes for different timestamps\n\
                            3. Chooses transaction timing for favorable result\n\
                            4. L2 sequencers have even more control\n\n\
                            Fix: Use Chainlink VRF for unpredictable randomness",
                            i
                        ),
                        location: i,
                    });
                }
            }

            // Pattern 2: DIFFICULTY/PREVRANDAO used for randomness (post-merge this is PREVRANDAO)
            if self.bytecode[i] == 0x44 { // DIFFICULTY/PREVRANDAO
                if i + 5 < self.bytecode.len() && self.bytecode[i + 1] == 0x06 { // MOD
                    vulnerabilities.push(VRFVulnerability {
                        vulnerability_type: VRFIssueType::MinerManipulableRandom,
                        severity: SecuritySeverity::High,
                        confidence: 0.85,
                        description: "PREVRANDAO/difficulty used as randomness (manipulable)".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Pre-merge: Miners manipulate difficulty\n\
                            2. Post-merge: PREVRANDAO from beacon chain\n\
                            3. While better than difficulty, still predictable\n\
                            4. Validators may have short-term influence\n\n\
                            Fix: Use Chainlink VRF for cryptographic randomness",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_chainlink_vrf(&self) -> bool {
        // Check for any VRF selector
        for selector in &self.vrf_selectors {
            if self.bytecode.windows(4).any(|w| w == *selector) {
                return true;
            }
        }
        false
    }

    fn has_vrf_coordinator_check(&self, pos: usize) -> bool {
        // Look for CALLER, SLOAD (vrfCoordinator), EQ pattern
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x33 && // CALLER
               i + 3 < self.bytecode.len() &&
               self.bytecode[i + 1] == 0x54 && // SLOAD
               self.bytecode[i + 2] == 0x14 { // EQ
                return true;
            }
        }
        false
    }

    fn has_randomness_usage_after(&self, pos: usize) -> bool {
        // Look for SSTORE or CALL after VRF callback (randomness is used)
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x55 || // SSTORE
               self.bytecode[i] == 0xF1 { // CALL
                return true;
            }
        }
        false
    }

    fn has_timestamp_delay_check(&self, pos: usize) -> bool {
        // Look for TIMESTAMP, SLOAD (commitTime), SUB, GT pattern
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 && // TIMESTAMP
               i + 4 < self.bytecode.len() &&
               self.bytecode[i + 1] == 0x54 && // SLOAD
               self.bytecode[i + 2] == 0x03 && // SUB
               self.bytecode[i + 3] == 0x11 { // GT
                return true;
            }
        }
        false
    }

    fn has_salt_in_commitment(&self, pos: usize) -> bool {
        // Look for CALLER or CALLDATALOAD in the hash preimage (salt)
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x33 || // CALLER (as salt)
               self.bytecode[i] == 0x35 { // CALLDATALOAD (explicit salt)
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockhash_manipulation() {
        let bytecode = vec![
            0x43, // NUMBER
            0x60, 0x01, // PUSH1 1
            0x03, // SUB (block.number - 1)
            0x40, // BLOCKHASH
            0x60, 0x64, // PUSH1 100
            0x06, // MOD (randomness)
        ];
        
        let detector = VRFRandomnessDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, VRFIssueType::PredictableBlockhash)));
    }

    #[test]
    fn test_timestamp_randomness() {
        let bytecode = vec![
            0x42, // TIMESTAMP
            0x60, 0x0A, // PUSH1 10
            0x06, // MOD
        ];
        
        let detector = VRFRandomnessDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, VRFIssueType::InsecureRandomness)));
    }

    #[test]
    fn test_attacker_controlled_seed() {
        let bytecode = vec![
            0x33, // CALLER
            0x42, // TIMESTAMP
            0x20, // KECCAK256 (hash of caller + timestamp)
        ];
        
        let detector = VRFRandomnessDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, VRFIssueType::AttackerControlledSeed)));
    }
}
