use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlatypusVulnerability {
    EmergencyPauseBypass { description: String, location: usize, confidence: f32 },
    FlashLoanDuringPause { description: String, location: usize, confidence: f32 },
}

pub struct PlatypusEmergencyPauseBypassDetector {
    bytecode: Vec<u8>,
}

impl PlatypusEmergencyPauseBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<PlatypusVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Platypus Feb 2023 $8.5M exploit: Flash loan executed during emergency pause
        for i in 0..self.bytecode.len().saturating_sub(60) {
            let section = &self.bytecode[i..std::cmp::min(i + 60, self.bytecode.len())];
            
            // Pattern: Flash loan or critical function without pause check
            let has_flash_loan = section.windows(4).any(|w| {
                w[0] == 0x63 && w[1] == 0x5c && w[2] == 0xde && w[3] == 0x28 // flashLoan selector
            });
            
            let has_pause_check = section.windows(10).any(|w| {
                w.contains(&0x54) && // SLOAD (read pause state)
                w.contains(&0x15) && // ISZERO (check if paused)
                w.contains(&0x57)    // JUMPI (revert if paused)
            });
            
            if has_flash_loan && !has_pause_check {
                vulnerabilities.push(PlatypusVulnerability::FlashLoanDuringPause {
                    description: format!("Platypus emergency pause bypass at PC {}. Feb 2023 $8.5M exploit: Flash loan function not protected by emergency pause. Attack: 1) Protocol pauses deposits/withdrawals, 2) Flash loan still active, 3) Attacker borrows flash loan, 4) Manipulates pool state, 5) Repays loan with profit. Fix: whenNotPaused modifier on ALL state-changing functions including flash loans.", i),
                    location: i,
                    confidence: 0.90,
                });
            }
        }
        
        vulnerabilities
    }
}
