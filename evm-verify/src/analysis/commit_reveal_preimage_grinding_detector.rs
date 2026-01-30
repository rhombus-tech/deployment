use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRevealVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CommitRevealPreimageGrindingDetector {
    bytecode: Vec<u8>,
}

impl CommitRevealPreimageGrindingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CommitRevealVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect KECCAK256 used for commitment without timestamp binding
        vulnerabilities.extend(self.detect_unbounded_commitment());
        
        // Detect SSTORE of hash without nonce/timestamp
        vulnerabilities.extend(self.detect_weak_commitment_storage());
        
        // Detect comparison against stored hash without time checks
        vulnerabilities.extend(self.detect_reveal_without_deadline());

        vulnerabilities
    }

    fn detect_unbounded_commitment(&self) -> Vec<CommitRevealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for KECCAK256 followed by SSTORE (commitment storage)
            if opcode == 0x20 { // KECCAK256
                let window_end = (pc + 30).min(self.bytecode.len());
                let mut found_sstore = false;
                let mut found_timestamp = false;
                
                // Check if TIMESTAMP or NUMBER used as input to hash
                let start = if pc > 20 { pc - 20 } else { 0 };
                found_timestamp = self.bytecode[start..pc].iter().any(|&b| b == 0x42 || b == 0x43); // TIMESTAMP or NUMBER
                
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x55 { // SSTORE
                        found_sstore = true;
                        break;
                    }
                }
                
                if found_sstore && !found_timestamp {
                    vulns.push(CommitRevealVulnerability {
                        pc,
                        vulnerability_type: "UnboundedCommitment".to_string(),
                        description: format!(
                            "KECCAK256 commitment at PC {} stored without timestamp/nonce binding. \
                            Attacker can grind preimages offline: generate millions of random values, \
                            hash them, and submit only favorable commitments. Include block.timestamp \
                            or block.number in hash input to prevent offline grinding: \
                            keccak256(abi.encodePacked(value, msg.sender, block.timestamp)).",
                            pc
                        ),
                        confidence: 0.80,
                    });
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_weak_commitment_storage(&self) -> Vec<CommitRevealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut hash_locations = Vec::new();

        // Find all KECCAK256 operations
        while pc < self.bytecode.len() {
            if self.bytecode[pc] == 0x20 {
                hash_locations.push(pc);
            }
            pc += 1;
        }

        // Check if CALLER is used with hash (binding to msg.sender)
        for &hash_pc in &hash_locations {
            let start = if hash_pc > 30 { hash_pc - 30 } else { 0 };
            let window = &self.bytecode[start..hash_pc];
            
            let has_caller = window.iter().any(|&b| b == 0x33); // CALLER
            let has_timestamp = window.iter().any(|&b| b == 0x42 || b == 0x43); // TIMESTAMP or NUMBER
            
            if !has_caller && !has_timestamp {
                vulns.push(CommitRevealVulnerability {
                    pc: hash_pc,
                    vulnerability_type: "WeakCommitmentBinding".to_string(),
                    description: format!(
                        "Commitment hash at PC {} lacks sender/timestamp binding. Without msg.sender \
                        in hash, attacker can: (1) Front-run favorable commitments from others, \
                        (2) Create commitments that work for any address. Always include msg.sender \
                        and block context in commitment hash to prevent these attacks.",
                        hash_pc
                    ),
                    confidence: 0.75,
                });
            }
        }

        vulns
    }

    fn detect_reveal_without_deadline(&self) -> Vec<CommitRevealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for EQ comparison (reveal checking) without TIMESTAMP check
            if opcode == 0x14 { // EQ
                let window_start = if pc > 50 { pc - 50 } else { 0 };
                let window_end = (pc + 50).min(self.bytecode.len());
                
                // Check if SLOAD is nearby (loading commitment)
                let has_sload = self.bytecode[window_start..window_end].iter().any(|&b| b == 0x54);
                
                // Check if TIMESTAMP is used for deadline checking
                let has_timestamp_check = self.bytecode[window_start..window_end].iter().any(|&b| b == 0x42);
                
                if has_sload && !has_timestamp_check {
                    vulns.push(CommitRevealVulnerability {
                        pc,
                        vulnerability_type: "NoRevealDeadline".to_string(),
                        description: format!(
                            "Commitment verification at PC {} without reveal deadline. Attacker can: \
                            (1) Delay reveal indefinitely until outcome is favorable, (2) Never reveal \
                            unfavorable commitments. Implement strict deadline: require(block.timestamp \
                            < commitTime + REVEAL_PERIOD). Consider slashing for non-reveal.",
                            pc
                        ),
                        confidence: 0.70,
                    });
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
