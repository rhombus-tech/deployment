/// Cryptographic Weakness Detector
/// Detects weak randomness, predictable RNG, and hash collision vulnerabilities
/// Critical for: Lotteries, NFT minting, gaming, any system requiring randomness

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CryptographicVulnerabilityType {
    WeakRandomness,              // Uses block.timestamp or blockhash for randomness
    PredictableRNG,              // Deterministic random number generation
    BlockhashManipulation,       // Miner-manipulable blockhash usage
    TimestampDependence,         // Critical logic depends on block.timestamp
    InsufficientEntropy,         // Not enough entropy sources
    HashCollisionRisk,           // Vulnerable to hash collision attacks
    ModuloBias,                  // Modulo bias in random number distribution
    FrontrunnableRandomness,     // Randomness can be front-run
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptographicVulnerability {
    pub vulnerability_type: CryptographicVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct CryptographicWeaknessDetector {
    bytecode: Vec<u8>,
}

impl CryptographicWeaknessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CryptographicVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_weak_randomness());
        vulnerabilities.extend(self.detect_blockhash_manipulation());
        vulnerabilities.extend(self.detect_timestamp_dependence());
        vulnerabilities.extend(self.detect_insufficient_entropy());
        vulnerabilities.extend(self.detect_modulo_bias());
        vulnerabilities.extend(self.detect_frontrunnable_randomness());

        vulnerabilities
    }

    fn detect_weak_randomness(&self) -> Vec<CryptographicVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect TIMESTAMP (0x42) used in modulo operations (random number generation)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if followed by MOD operation
                let end_10 = (i + 10).min(self.bytecode.len());
                let has_modulo = self.bytecode[i..end_10].iter().any(|&op| op == 0x06);

                // Check if used in KECCAK256 for randomness
                let has_keccak = self.bytecode[i..end_10].iter().any(|&op| op == 0x20);

                if has_modulo || has_keccak {
                    // Check for additional entropy sources
                    let end_20 = (i + 20).min(self.bytecode.len());
                    let has_additional_entropy = if end_20 > i + 5 {
                        self.bytecode[i..end_20].windows(5).any(|w| {
                            w.contains(&0x40) || // BLOCKHASH
                            w.contains(&0x43) || // NUMBER
                            w.contains(&0x33) || // CALLER
                            w.contains(&0x41)    // COINBASE
                        })
                    } else {
                        false
                    };

                    if !has_additional_entropy {
                        vulnerabilities.push(CryptographicVulnerability {
                            vulnerability_type: CryptographicVulnerabilityType::WeakRandomness,
                            severity: SecuritySeverity::Critical,
                            location: i,
                            description: "Uses block.timestamp alone for randomness. Miners can manipulate ±15 seconds.".to_string(),
                            remediation: "Use Chainlink VRF or combine multiple entropy sources: keccak256(abi.encodePacked(blockhash, timestamp, nonce))".to_string(),
                        });
                    } else {
                        vulnerabilities.push(CryptographicVulnerability {
                            vulnerability_type: CryptographicVulnerabilityType::WeakRandomness,
                            severity: SecuritySeverity::High,
                            location: i,
                            description: "Randomness uses on-chain data (predictable). All values known before transaction execution.".to_string(),
                            remediation: "Use commit-reveal scheme or off-chain oracle like Chainlink VRF.".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_blockhash_manipulation(&self) -> Vec<CryptographicVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect BLOCKHASH (0x40) usage
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x40 { // BLOCKHASH
                // Check what block number is being used
                let uses_current_block = self.bytecode[i.saturating_sub(5)..i].iter().any(|&op| {
                    op == 0x43 // NUMBER (current block)
                });

                // Check for proper block age validation
                let end_30 = (i + 30).min(self.bytecode.len());
                let has_age_check = if end_30 > i + 5 {
                    self.bytecode[i..end_30].windows(5).any(|w| {
                        w.contains(&0x03) && // SUB (block.number - targetBlock)
                        w.contains(&0x10)    // LT (age < 256)
                    })
                } else {
                    false
                };

                if uses_current_block {
                    vulnerabilities.push(CryptographicVulnerability {
                        vulnerability_type: CryptographicVulnerabilityType::BlockhashManipulation,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Uses blockhash(block.number) which is always 0. Current block hash unknown during execution.".to_string(),
                        remediation: "Use blockhash(block.number - 1) or earlier blocks for randomness.".to_string(),
                    });
                }

                if !has_age_check {
                    vulnerabilities.push(CryptographicVulnerability {
                        vulnerability_type: CryptographicVulnerabilityType::BlockhashManipulation,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Doesn't validate block age. Blockhash returns 0 for blocks older than 256 blocks.".to_string(),
                        remediation: "Check age: require(block.number - targetBlock < 256, 'Block too old')".to_string(),
                    });
                }

                // Check if blockhash used in high-value operations
                let near_transfer = if i + 50 <= self.bytecode.len() {
                    self.bytecode[i..i + 50].iter().any(|&op| op == 0xf1 || op == 0xa9) // CALL or SELFDESTRUCT
                } else {
                    false
                };

                if near_transfer {
                    vulnerabilities.push(CryptographicVulnerability {
                        vulnerability_type: CryptographicVulnerabilityType::BlockhashManipulation,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Blockhash-based randomness controls fund transfers. Miners can manipulate outcomes.".to_string(),
                        remediation: "For high-value randomness, use Chainlink VRF or similar oracle service.".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_timestamp_dependence(&self) -> Vec<CryptographicVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for TIMESTAMP in conditional logic
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if used in critical conditionals
                let end_15 = (i + 15).min(self.bytecode.len());
                let in_conditional = if end_15 > i + 3 {
                    self.bytecode[i + 3..end_15].windows(3).any(|w| {
                        (w[0] == 0x10 || w[0] == 0x11) && // LT or GT
                        w[1] == 0x57 // JUMPI
                    })
                } else {
                    false
                };

                // Check if affects fund flow
                let end_20_funds = (i + 20).min(self.bytecode.len());
                let affects_funds = if end_20_funds > i {
                    self.bytecode[i..end_20_funds].iter().any(|&op| op == 0xf1 || op == 0xa9) // CALL or SELFDESTRUCT
                } else {
                    false
                };

                // Check if used with equality (dangerous)
                let end_10_eq = (i + 10).min(self.bytecode.len());
                let uses_equality = if end_10_eq > i + 1 {
                    self.bytecode[i + 1..end_10_eq].iter().any(|&op| op == 0x14) // EQ
                } else {
                    false
                };

                if in_conditional && affects_funds {
                    vulnerabilities.push(CryptographicVulnerability {
                        vulnerability_type: CryptographicVulnerabilityType::TimestampDependence,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Critical fund flow depends on block.timestamp. Miners have ±15 second manipulation window.".to_string(),
                        remediation: "Use block.number for time-based logic or accept timestamp variance as acceptable risk.".to_string(),
                    });
                }

                if uses_equality {
                    vulnerabilities.push(CryptographicVulnerability {
                        vulnerability_type: CryptographicVulnerabilityType::TimestampDependence,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Uses equality check on block.timestamp (if timestamp == X). Exact match unlikely.".to_string(),
                        remediation: "Use range checks: if (timestamp >= startTime && timestamp < endTime)".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_insufficient_entropy(&self) -> Vec<CryptographicVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for KECCAK256 (0x20) used for randomness
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x20 { // KECCAK256
                // Count entropy sources before the hash
                let window = &self.bytecode[i.saturating_sub(30)..i];
                
                let entropy_sources = [
                    (0x42, "TIMESTAMP"),
                    (0x40, "BLOCKHASH"),
                    (0x43, "NUMBER"),
                    (0x33, "CALLER"),
                    (0x41, "COINBASE"),
                    (0x48, "BASEFEE"),
                ];

                let source_count = entropy_sources
                    .iter()
                    .filter(|(op, _)| window.contains(op))
                    .count();

                // Check if result used in modulo (random selection)
                let end_10_rand = (i + 10).min(self.bytecode.len());
                let used_for_random = if end_10_rand > i + 1 {
                    self.bytecode[i + 1..end_10_rand].iter().any(|&op| op == 0x06)
                } else {
                    false
                };

                if used_for_random && source_count < 2 {
                    vulnerabilities.push(CryptographicVulnerability {
                        vulnerability_type: CryptographicVulnerabilityType::InsufficientEntropy,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: format!("Randomness uses only {} entropy source(s). Easily predictable.", source_count),
                        remediation: "Combine multiple sources: keccak256(abi.encodePacked(blockhash, timestamp, caller, nonce))".to_string(),
                    });
                }

                // Check if nonce or counter is included
                let has_nonce = if i >= 3 {
                    self.bytecode[i - 3..i].windows(3).any(|w| {
                        w[0] == 0x54 && // SLOAD (reading nonce)
                        w[1] == 0x60 && // PUSH1
                        w[2] == 0x01    // 1 (incrementing)
                    })
                } else {
                    false
                };

                if used_for_random && !has_nonce {
                    vulnerabilities.push(CryptographicVulnerability {
                        vulnerability_type: CryptographicVulnerabilityType::InsufficientEntropy,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Randomness lacks nonce/counter. Same inputs produce same outputs.".to_string(),
                        remediation: "Include incrementing nonce in hash input to ensure uniqueness per call.".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_modulo_bias(&self) -> Vec<CryptographicVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect MOD (0x06) operations on random numbers
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x06 { // MOD
                // Check if modulo operand is not a power of 2
                let before_mod = &self.bytecode[i.saturating_sub(5)..i];
                
                // Look for PUSH opcodes (0x60-0x7f) that indicate the modulo value
                let has_non_power_of_2 = before_mod.windows(2).any(|w| {
                    if w[0] >= 0x60 && w[0] <= 0x7f {
                        // Check if value is not a power of 2
                        let value = w[1] as u32;
                        value > 0 && !value.is_power_of_two()
                    } else {
                        false
                    }
                });

                // Check if this is used in random selection
                let from_random_source = if i >= 20 {
                    self.bytecode[i - 20..i].iter().any(|&op| {
                        op == 0x20 || // KECCAK256
                        op == 0x40 || // BLOCKHASH
                        op == 0x42    // TIMESTAMP
                    })
                } else {
                    false
                };

                if from_random_source && has_non_power_of_2 {
                    vulnerabilities.push(CryptographicVulnerability {
                        vulnerability_type: CryptographicVulnerabilityType::ModuloBias,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Modulo on non-power-of-2 introduces bias. Some outcomes more likely than others.".to_string(),
                        remediation: "Use rejection sampling: while (rand >= maxValid) { rand = newRandom(); }".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_frontrunnable_randomness(&self) -> Vec<CryptographicVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for randomness generation patterns
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Pattern: Load random value and immediately use it
            if self.bytecode[i] == 0x20 { // KECCAK256 (random generation)
                // Check if there's a commit-reveal pattern
                let has_commit_phase = if i >= 4 {
                    self.bytecode[i - 4..i].windows(4).any(|w| {
                        w == &[0xc4, 0x8d, 0x2e, 0x5a] || // commit(bytes32)
                        w == &[0xa5, 0x7e, 0xc3, 0x4f]    // reveal(uint256, bytes32)
                    })
                } else {
                    false
                };

                // Check if value stored before use (commit)
                let end_20_store = (i + 20).min(self.bytecode.len());
                let stores_before_use = if end_20_store > i + 3 {
                    self.bytecode[i + 3..end_20_store].windows(3).any(|w| {
                        w[0] == 0x55 && // SSTORE (save commit)
                        w[1] != 0xf1    // Not immediately followed by CALL
                    })
                } else {
                    false
                };

                // Check if randomness affects value transfer
                let end_40 = (i + 40).min(self.bytecode.len());
                let affects_transfer = if end_40 > i {
                    self.bytecode[i..end_40].iter().any(|&op| op == 0xf1 || op == 0xa9) // CALL or SELFDESTRUCT
                } else {
                    false
                };

                if affects_transfer && !has_commit_phase && !stores_before_use {
                    vulnerabilities.push(CryptographicVulnerability {
                        vulnerability_type: CryptographicVulnerabilityType::FrontrunnableRandomness,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Randomness generated and used in same transaction. Attacker can simulate outcome and front-run.".to_string(),
                        remediation: "Implement commit-reveal: commit hash in tx1, reveal value in tx2 after waiting period.".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_weak_randomness() {
        let bytecode = vec![
            0x42, // TIMESTAMP
            0x60, 0x0a, // PUSH1 10
            0x06, // MOD (timestamp % 10)
        ];

        let detector = CryptographicWeaknessDetector::new(bytecode);
        let vulnerabilities = detector.detect_vulnerabilities();

        assert!(vulnerabilities.iter().any(|v| {
            matches!(v.vulnerability_type, CryptographicVulnerabilityType::WeakRandomness)
        }));
    }

    #[test]
    fn test_detect_blockhash_manipulation() {
        let bytecode = vec![
            0x43, // NUMBER (current block)
            0x40, // BLOCKHASH (blockhash of current block = 0)
        ];

        let detector = CryptographicWeaknessDetector::new(bytecode);
        let vulnerabilities = detector.detect_vulnerabilities();

        assert!(vulnerabilities.iter().any(|v| {
            matches!(v.vulnerability_type, CryptographicVulnerabilityType::BlockhashManipulation)
        }));
    }

    #[test]
    fn test_safe_randomness() {
        let bytecode = vec![
            0xc4, 0x8d, 0x2e, 0x5a, // commit(bytes32)
            0xa5, 0x7e, 0xc3, 0x4f, // reveal(uint256, bytes32)
            0x40, // BLOCKHASH
            0x42, // TIMESTAMP
            0x33, // CALLER
            0x20, // KECCAK256 (multiple sources)
            0x06, // MOD
        ];

        let detector = CryptographicWeaknessDetector::new(bytecode);
        let vulnerabilities = detector.detect_vulnerabilities();

        let critical_vulns: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
            .collect();

        assert!(critical_vulns.is_empty() || critical_vulns.len() < 2);
    }
}
