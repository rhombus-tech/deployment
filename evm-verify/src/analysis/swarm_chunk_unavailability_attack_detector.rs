use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SwarmChunkUnavailabilityAttackDetector {
    bytecode: Vec<u8>,
}

impl SwarmChunkUnavailabilityAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SwarmVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_chunk_verification());
        vulnerabilities.extend(self.detect_postage_stamp_manipulation());
        vulnerabilities.extend(self.detect_neighborhood_eclipse_risk());

        vulnerabilities
    }

    fn detect_missing_chunk_verification(&self) -> Vec<SwarmVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External call that might be fetching Swarm chunks
            if matches!(opcode, 0xF1 | 0xFA) {
                let mut check_pc = pc + 1;
                let mut found_sstore = false;
                let mut has_hash_verification = false;
                let mut instructions = 0;

                while check_pc < self.bytecode.len() && instructions < 60 {
                    let check_op = self.bytecode[check_pc];
                    
                    if check_op == 0x55 { // SSTORE
                        found_sstore = true;
                    }
                    
                    // Check for Keccak256 hash verification
                    if check_op == 0x20 { // KECCAK256
                        has_hash_verification = true;
                    }
                    
                    check_pc += 1;
                    instructions += 1;
                    
                    if check_op >= 0x60 && check_op <= 0x7F {
                        check_pc += (check_op - 0x5F) as usize;
                    }
                }

                if found_sstore && !has_hash_verification {
                    vulns.push(SwarmVulnerability {
                        pc,
                        vulnerability_type: "MissingChunkVerification".to_string(),
                        description: format!(
                            "Swarm chunk retrieval at PC {} without content-addressed hash verification. \
                            Missing validation of: chunk integrity via BMT (Binary Merkle Tree) hash, \
                            content authenticity, chunk completeness. Attacker can: serve corrupted chunks, \
                            provide fake data matching chunk reference, execute data poisoning attacks. \
                            Swarm's content-addressing requires cryptographic verification.",
                            pc
                        ),
                        confidence: 0.85,
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

    fn detect_postage_stamp_manipulation(&self) -> Vec<SwarmVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // SSTORE operations that might store Swarm references
            if opcode == 0x55 {
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for 32-byte references (Swarm chunk addresses)
                let has_swarm_ref = window.windows(2).any(|w| w[0] == 0x60 && w[1] == 0x20);
                
                if has_swarm_ref {
                    // Check for postage stamp validation
                    // Look for: timestamp checks, batch owner verification, signature validation
                    let has_timestamp_check = window.iter().any(|&b| b == 0x42);
                    let has_signature_check = window.iter().any(|&b| b == 0x01); // ECRECOVER
                    
                    if !has_timestamp_check && !has_signature_check {
                        vulns.push(SwarmVulnerability {
                            pc,
                            vulnerability_type: "PostageStampManipulation".to_string(),
                            description: format!(
                                "Swarm reference stored at PC {} without postage stamp validation. \
                                Missing checks for: batch validity, stamp expiration, batch depth sufficiency, \
                                postage batch owner authorization. Enables: storing data with expired stamps, \
                                using invalid postage batches, chunk unavailability after stamp expiry, \
                                denial of service via premature chunk garbage collection.",
                                pc
                            ),
                            confidence: 0.82,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_neighborhood_eclipse_risk(&self) -> Vec<SwarmVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut external_calls = 0;
        let mut unique_address_checks = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xFA) {
                external_calls += 1;
            }
            
            // Look for address diversity checks (XOR for proximity)
            if opcode == 0x18 { // XOR
                unique_address_checks += 1;
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // If making external calls without redundancy checks
        if external_calls > 0 && unique_address_checks == 0 {
            vulns.push(SwarmVulnerability {
                pc: 0,
                vulnerability_type: "NeighborhoodEclipseRisk".to_string(),
                description: format!(
                    "Contract makes {} Swarm node calls without neighborhood diversity checks. \
                    Vulnerable to: Kademlia neighborhood eclipse attacks, single-node dependency, \
                    targeted chunk unavailability. Missing protections: proximity order validation, \
                    redundant node selection, neighborhood diversity enforcement. Attacker controlling \
                    nearby nodes in Kademlia space can eclipse target chunks and cause unavailability.",
                    external_calls
                ),
                confidence: 0.78,
            });
        }

        vulns
    }
}
