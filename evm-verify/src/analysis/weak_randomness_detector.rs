/// Weak Randomness Detector
/// 
/// Detects use of predictable sources for randomness:
/// - block.timestamp
/// - block.number  
/// - blockhash
/// - block.difficulty (now prevrandao post-merge, still predictable)
///
/// These are manipulable by miners/validators!
/// Proper solution: Chainlink VRF or commit-reveal

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakRandomness {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub randomness_source: RandomnessSource,
    pub predictability: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RandomnessSource {
    Timestamp,       // block.timestamp
    BlockNumber,     // block.number
    BlockHash,       // blockhash(n)
    Difficulty,      // block.difficulty / block.prevrandao
    TxOrigin,        // tx.origin (very weak)
    MsgSender,       // msg.sender (predictable)
}

pub struct WeakRandomnessDetector {
    bytecode: Vec<u8>,
}

impl WeakRandomnessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<WeakRandomness> {
        let mut vulnerabilities = Vec::new();
        
        vulnerabilities.extend(self.detect_timestamp_randomness());
        vulnerabilities.extend(self.detect_blockhash_randomness());
        vulnerabilities.extend(self.detect_block_number_randomness());
        vulnerabilities.extend(self.detect_difficulty_randomness());
        vulnerabilities.extend(self.detect_address_randomness());
        
        vulnerabilities
    }
    
    fn detect_timestamp_randomness(&self) -> Vec<WeakRandomness> {
        let mut vulns = Vec::new();
        
        // Pattern: TIMESTAMP followed by MOD (used for random selection)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Look for MOD operation (random selection)
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 { // MOD
                        vulns.push(WeakRandomness {
                            vulnerability_type: "Weak Randomness - Timestamp".to_string(),
                            severity: "High".to_string(),
                            location: i,
                            description: "Using block.timestamp for randomness".to_string(),
                            randomness_source: RandomnessSource::Timestamp,
                            predictability: "Miners can manipulate timestamp within ~15 seconds".to_string(),
                            exploit_scenario: 
                                "Lottery using timestamp % numPlayers:\n\
                                 1. Miner sees profitable outcome\n\
                                 2. Miner adjusts timestamp by few seconds\n\
                                 3. Changes winner to miner's address\n\
                                 4. Miner wins unfairly".to_string(),
                            remediation: "Use Chainlink VRF for secure randomness".to_string(),
                        });
                        break;
                    }
                }
            }
        }
        
        vulns
    }
    
    fn detect_blockhash_randomness(&self) -> Vec<WeakRandomness> {
        let mut vulns = Vec::new();
        
        // Pattern: BLOCKHASH opcode used for randomness
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x40 { // BLOCKHASH
                vulns.push(WeakRandomness {
                    vulnerability_type: "Weak Randomness - Blockhash".to_string(),
                    severity: "Critical".to_string(),
                    location: i,
                    description: "Using blockhash for randomness".to_string(),
                    randomness_source: RandomnessSource::BlockHash,
                    predictability: "Blockhash only available for last 256 blocks, returns 0 otherwise".to_string(),
                    exploit_scenario: 
                        "1. Attacker waits 256 blocks\n\
                         2. blockhash returns 0 (predictable)\n\
                         3. Or miner withholds block if unfavorable hash".to_string(),
                    remediation: "Never use blockhash for randomness. Use VRF.".to_string(),
                });
            }
        }
        
        vulns
    }
    
    fn detect_block_number_randomness(&self) -> Vec<WeakRandomness> {
        let mut vulns = Vec::new();
        
        // Pattern: NUMBER followed by MOD
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x43 { // NUMBER
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 { // MOD
                        vulns.push(WeakRandomness {
                            vulnerability_type: "Weak Randomness - Block Number".to_string(),
                            severity: "Medium".to_string(),
                            location: i,
                            description: "Using block.number for randomness".to_string(),
                            randomness_source: RandomnessSource::BlockNumber,
                            predictability: "Block number is entirely predictable".to_string(),
                            exploit_scenario: "Attacker knows exact block number, can predict outcome".to_string(),
                            remediation: "Use Chainlink VRF".to_string(),
                        });
                        break;
                    }
                }
            }
        }
        
        vulns
    }
    
    fn detect_difficulty_randomness(&self) -> Vec<WeakRandomness> {
        let mut vulns = Vec::new();
        
        // Pattern: DIFFICULTY opcode (now PREVRANDAO post-merge)
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x44 { // DIFFICULTY / PREVRANDAO
                vulns.push(WeakRandomness {
                    vulnerability_type: "Weak Randomness - Difficulty/Prevrandao".to_string(),
                    severity: "High".to_string(),
                    location: i,
                    description: "Using block.difficulty or block.prevrandao for randomness".to_string(),
                    randomness_source: RandomnessSource::Difficulty,
                    predictability: "Validators can influence prevrandao output".to_string(),
                    exploit_scenario: 
                        "Post-merge (PoS):\n\
                         Validators reveal prevrandao after seeing transactions\n\
                         Can skip block if unfavorable randomness".to_string(),
                    remediation: "Use Chainlink VRF for verifiable randomness".to_string(),
                });
            }
        }
        
        vulns
    }
    
    fn detect_address_randomness(&self) -> Vec<WeakRandomness> {
        let mut vulns = Vec::new();
        
        // Pattern: CALLER or ORIGIN used with MOD (very weak randomness)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x33 || self.bytecode[i] == 0x32 { // CALLER or ORIGIN
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 { // MOD
                        let source = if self.bytecode[i] == 0x33 {
                            RandomnessSource::MsgSender
                        } else {
                            RandomnessSource::TxOrigin
                        };
                        
                        vulns.push(WeakRandomness {
                            vulnerability_type: "Weak Randomness - Address".to_string(),
                            severity: "Critical".to_string(),
                            location: i,
                            description: "Using msg.sender or tx.origin for randomness".to_string(),
                            randomness_source: source,
                            predictability: "Attacker fully controls their address".to_string(),
                            exploit_scenario: "Attacker tries from multiple addresses until winning".to_string(),
                            remediation: "Never use addresses for randomness. Use VRF.".to_string(),
                        });
                        break;
                    }
                }
            }
        }
        
        vulns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_timestamp_randomness() {
        let bytecode = vec![
            0x42,              // TIMESTAMP
            0x60, 0x0A,        // PUSH1 10
            0x06,              // MOD (timestamp % 10 for "random")
        ];
        
        let detector = WeakRandomnessDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.len() > 0);
    }
    
    #[test]
    fn test_blockhash_randomness() {
        let bytecode = vec![
            0x60, 0x01,        // PUSH1 1
            0x40,              // BLOCKHASH
        ];
        
        let detector = WeakRandomnessDetector::new(bytecode);
        let vulns = detector.detect_blockhash_randomness();
        
        assert!(vulns.len() > 0);
    }
}
