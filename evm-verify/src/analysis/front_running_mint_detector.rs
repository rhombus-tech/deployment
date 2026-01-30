/// Front-Running Mint Detector
/// Detects minting before transfers to steal fees/rewards
/// Vulnerable pattern: Public mint function without access control that can be front-run

use crate::bytecode::SecurityFinding;

pub struct FrontRunningMintDetector {
    bytecode: Vec<u8>,
}

impl FrontRunningMintDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(location) = self.has_frontrunnable_mint() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Front-running mint vulnerability at PC {}. Public mint function without access control allows attackers to front-run user transactions and steal fees/rewards",
                    location
                ),
                pc: location,
                confidence: 0.87,
            });
        }

        findings
    }

    fn has_frontrunnable_mint(&self) -> Option<usize> {
        // Look for mint function signature patterns
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Check for common mint function selectors
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() { // PUSH4
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Common mint selectors: mint(address,uint256) = 0x40c10f19
                // mintTo(address) = 0x449a52f8
                if selector == 0x40c10f19 || selector == 0x449a52f8 {
                    // Check if there's NO access control (no CALLER check before mint)
                    let has_access_control = self.has_access_control_before(i);
                    
                    // Check if followed by state change (SSTORE for balance update)
                    let has_state_change = self.has_state_change_after(i);
                    
                    if !has_access_control && has_state_change {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_access_control_before(&self, mint_pos: usize) -> bool {
        let start = mint_pos.saturating_sub(50);
        
        // Look for access control patterns: CALLER, EQ, ISZERO, REVERT
        for i in start..mint_pos {
            if self.bytecode[i] == 0x33 { // CALLER
                // Check for comparison within next 10 bytes
                for j in (i + 1)..(i + 10).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    // Look for EQ (0x14) or access control check
                    if self.bytecode[j] == 0x14 {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_state_change_after(&self, mint_pos: usize) -> bool {
        let end = (mint_pos + 100).min(self.bytecode.len());
        
        for i in mint_pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x55 { // SSTORE (balance update)
                return true;
            }
        }
        false
    }
}
