use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VelodromeVulnerability {
    VeNFTVotingManipulation { description: String, location: usize, confidence: f32 },
    BribeDistributionExploit { description: String, location: usize, confidence: f32 },
}

pub struct VelodromeVeNFTVotingDetector {
    bytecode: Vec<u8>,
}

impl VelodromeVeNFTVotingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<VelodromeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Velodrome/Aerodrome: veNFT voting for emissions + bribes
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Pattern: Vote weight without decay check
            let has_vote = section.windows(12).any(|w| {
                w.contains(&0x54) && // SLOAD (veNFT balance)
                w.contains(&0x02) && // MUL (calculate vote power)
                w.contains(&0x55)    // SSTORE (record vote)
            });
            
            let no_decay = !section.windows(10).any(|w| {
                w.contains(&0x42) && // TIMESTAMP (lock expiry)
                w.contains(&0x04)    // DIV (decay calc)
            });
            
            if has_vote && no_decay {
                vulnerabilities.push(VelodromeVulnerability::VeNFTVotingManipulation {
                    description: format!("veNFT voting manipulation at PC {}. Velodrome mechanics: Lock VELO → get veNFT → vote for pool emissions → receive bribes. Vote power = lock_amount * lock_duration. Attack: 1) Flash loan VELO, 2) Lock for max duration (4 years) → massive vote power, 3) Vote for attacker's pool → direct all emissions, 4) Unlock (if allowed) or sell veNFT. Real risk: Convex-style vote power accumulation. Mitigation: Vote weight decay over time, no flash loan voting (check balance held 1+ epoch), snapshot-based voting.", i),
                    location: i,
                    confidence: 0.87,
                });
            }
            
            // Pattern: Bribe claim without vote verification
            let has_bribe_claim = section.windows(10).any(|w| {
                w.contains(&0x54) && // SLOAD (bribe balance)
                w.contains(&0xF1)    // CALL (transfer bribe)
            });
            
            let no_vote_check = !section.windows(12).any(|w| {
                w.contains(&0x54) && // SLOAD (vote record)
                w.contains(&0x14)    // EQ (verify voted)
            });
            
            if has_bribe_claim && no_vote_check {
                vulnerabilities.push(VelodromeVulnerability::BribeDistributionExploit {
                    description: format!("Bribe distribution exploit at PC {}. Bribes paid to veNFT holders who vote for specific pools. Risk: Claim bribes without actually voting, or vote manipulation. Attack: 1) Create veNFT, 2) Vote for pool A, 3) Claim bribes for pool B (no verification), 4) Receive all bribes. Or: Vote, claim bribe, change vote → double-claim. Mitigation: Atomic vote + bribe claim, verify vote before bribe transfer, 1-epoch delay between vote change and new bribe eligibility.", i),
                    location: i,
                    confidence: 0.83,
                });
            }
        }
        
        vulnerabilities
    }
}
