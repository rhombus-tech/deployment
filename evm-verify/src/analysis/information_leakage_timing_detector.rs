use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InformationLeakageVulnerability {
    TimingSideChannel { description: String, location: usize, confidence: f32 },
    GasPatternLeakage { description: String, location: usize, confidence: f32 },
    BranchingLeakage { description: String, location: usize, confidence: f32 },
}

pub struct InformationLeakageTimingDetector {
    bytecode: Vec<u8>,
}

impl InformationLeakageTimingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<InformationLeakageVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            let section = &self.bytecode[i..std::cmp::min(i + 80, self.bytecode.len())];
            
            // Pattern 1: Conditional logic on secret data
            let has_secret_load = section.windows(12).any(|w| {
                w.contains(&0x54) // SLOAD (potentially secret)
            });
            
            let has_conditional = section.windows(15).any(|w| {
                (w.contains(&0x10) || w.contains(&0x11)) && w.contains(&0x57) // (LT or GT) + JUMPI
            });
            
            if has_secret_load && has_conditional {
                vulnerabilities.push(InformationLeakageVulnerability::TimingSideChannel {
                    description: format!("Timing side-channel at PC {}. Secret data affects execution path. Attack: Gas usage reveals which branch taken → reveals secret. Information theory: Each branch leaks log₂(branches) bits. Example: if (password == secret) {{...}} else {{...}} → gas differs → attacker learns password bit by bit. Real: Timing attacks on cryptographic implementations. Channel capacity C = log₂(paths) bits/tx. Mitigation: Constant-time execution, or accept that all data on-chain is public (can't have secrets).", i),
                    location: i,
                    confidence: 0.87,
                });
            }
            
            // Pattern 2: Loop iterations dependent on private data
            let has_loop = section.windows(20).any(|w| {
                w.contains(&0x56) || w.contains(&0x57) // JUMP or JUMPI (loop)
            });
            
            if has_secret_load && has_loop {
                vulnerabilities.push(InformationLeakageVulnerability::GasPatternLeakage {
                    description: format!("Gas pattern leakage at PC {}. Loop iterations reveal private data. Attack: Count gas → deduce iteration count → reveals secret length/value. Example: for(i=0; i<secretLength; i++) → gas = base + iter*cost → secretLength = (gas-base)/cost. Binary search on secret: log₂(N) queries. Mitigation: Pad to constant iterations, or make all data public.", i),
                    location: i,
                    confidence: 0.82,
                });
            }
            
            // Pattern 3: Early return based on secret
            let has_revert = section.contains(&0xFD); // REVERT
            if has_secret_load && has_revert && has_conditional {
                vulnerabilities.push(InformationLeakageVulnerability::BranchingLeakage {
                    description: format!("Branching leakage at PC {}. Early exit reveals information. Attack: Transaction reverts or succeeds based on secret → binary search narrows secret. Example: require(input == secret) → attacker tries input=0,1,2... → when tx succeeds, found secret. Information leaked: log₂(search space) bits via revert/success. Mitigation: No secret-dependent reverts, or commit-reveal pattern.", i),
                    location: i,
                    confidence: 0.85,
                });
            }
        }
        
        vulnerabilities
    }
}
