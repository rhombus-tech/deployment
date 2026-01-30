/// Order Flow Auction Detector
use crate::bytecode::SecurityFinding;

pub struct OrderFlowAuctionDetector {
    bytecode: Vec<u8>,
}

impl OrderFlowAuctionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_exploit_pattern() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Order flow auction manipulation at PC {}", location),
                pc: location,
                confidence: 0.84,
            });
        }
        findings
    }

    fn detect_exploit_pattern(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if i >= self.bytecode.len() { break; }
            
            if self.matches_exploit_signature(i) && self.has_exploit_context(i) {
                return Some(i);
            }
        }
        None
    }

    fn matches_exploit_signature(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        match self.bytecode[pos] {
            0xf1 | 0xf4 | 0xfa => { // External calls
                // Bridge/L2/cross-chain patterns
                if pos + 50 < self.bytecode.len() {
                    self.check_bridge_pattern(pos)
                } else {
                    false
                }
            },
            0x54 => { // SLOAD
                // Oracle/state manipulation
                if pos + 40 < self.bytecode.len() {
                    self.check_oracle_manipulation(pos)
                } else {
                    false
                }
            },
            0x55 => { // SSTORE
                // Rewards/points manipulation
                if pos + 30 < self.bytecode.len() {
                    self.check_reward_manipulation(pos)
                } else {
                    false
                }
            },
            0x31 | 0x47 => { // BALANCE/SELFBALANCE
                // Slashing/staking exploits
                if pos + 30 < self.bytecode.len() {
                    self.check_slashing_pattern(pos)
                } else {
                    false
                }
            },
            0x20 => { // KECCAK256
                // Intent/signature patterns
                if pos + 40 < self.bytecode.len() {
                    self.check_intent_pattern(pos)
                } else {
                    false
                }
            },
            0x01 => { // ECRECOVER
                // Private key/signature patterns
                if pos + 30 < self.bytecode.len() {
                    self.check_signature_safety(pos)
                } else {
                    false
                }
            },
            _ => false,
        }
    }

    fn has_exploit_context(&self, pos: usize) -> bool {
        let end = (pos + 60).min(self.bytecode.len());
        
        let mut has_external_call = false;
        let mut has_state_change = false;
        let mut has_value_transfer = false;
        let mut has_complex_math = false;
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            
            match self.bytecode[i] {
                0xf1 | 0xfa | 0xf4 => has_external_call = true,
                0x55 => has_state_change = true,
                0x00 if i > 0 && self.bytecode[i-1] == 0xf1 => has_value_transfer = true,
                0x02 | 0x04 | 0x05 | 0x06 => has_complex_math = true,
                _ => {}
            }
        }
        
        // Exploit requires multiple suspicious patterns
        (has_external_call && has_state_change) || 
        (has_value_transfer && has_complex_math) ||
        (has_state_change && has_complex_math)
    }

    fn check_bridge_pattern(&self, pos: usize) -> bool {
        let end = (pos + 50).min(self.bytecode.len());
        
        for i in (pos + 1)..end {
            if i >= self.bytecode.len() { break; }
            // Bridge message passing
            if self.bytecode[i] == 0x20 { // KECCAK256 for message hash
                if i + 10 < self.bytecode.len() {
                    if self.bytecode[i + 5] == 0x54 { // SLOAD for verification
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check_oracle_manipulation(&self, pos: usize) -> bool {
        let end = (pos + 40).min(self.bytecode.len());
        let mut read_count = 0;
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x54 {
                read_count += 1;
            }
            if self.bytecode[i] == 0x02 || self.bytecode[i] == 0x04 {
                // Price calculations
                if read_count > 0 {
                    return true;
                }
            }
        }
        false
    }

    fn check_reward_manipulation(&self, pos: usize) -> bool {
        if pos < 20 || pos + 30 >= self.bytecode.len() { return false; }
        
        // Look for reward calculation before storage
        for i in pos.saturating_sub(20)..pos {
            if i >= self.bytecode.len() { break; }
            if matches!(self.bytecode[i], 0x02 | 0x04) { // MUL/DIV
                return true;
            }
        }
        false
    }

    fn check_slashing_pattern(&self, pos: usize) -> bool {
        let end = (pos + 30).min(self.bytecode.len());
        
        for i in (pos + 1)..end {
            if i >= self.bytecode.len() { break; }
            // Balance used in slashing calc
            if matches!(self.bytecode[i], 0x03 | 0x04) { // SUB/DIV
                if i + 5 < self.bytecode.len() {
                    if self.bytecode[i + 3] == 0x55 { // SSTORE
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check_intent_pattern(&self, pos: usize) -> bool {
        let end = (pos + 40).min(self.bytecode.len());
        
        for i in (pos + 1)..end {
            if i >= self.bytecode.len() { break; }
            // Intent hash followed by call
            if matches!(self.bytecode[i], 0xf1 | 0xfa) {
                return true;
            }
        }
        false
    }

    fn check_signature_safety(&self, pos: usize) -> bool {
        let end = (pos + 30).min(self.bytecode.len());
        
        for i in (pos + 1)..end {
            if i >= self.bytecode.len() { break; }
            // Ecrecover without proper validation
            if self.bytecode[i] == 0x14 { // EQ check
                return false; // Has validation
            }
        }
        true // No validation found
    }
}
