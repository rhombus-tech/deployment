/// NFT Wash Trading Detector
use crate::bytecode::SecurityFinding;

pub struct NftWashTradingDetector {
    bytecode: Vec<u8>,
}

impl NftWashTradingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("NFT wash trading vulnerability at PC {}", location),
                pc: location,
                confidence: 0.86,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_wash_trading(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_wash_trading(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for NFT marketplace without wash trading prevention
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // fulfillOrder, matchOrders, buy, sell selectors
            if matches!(self.bytecode[pos+1], 0x3b | 0x5a | 0x7c | 0xa9) {
                let mut has_buyer_seller_check = false;
                let mut has_cooling_period = false;
                let mut has_royalty_tracking = false;
                let mut checks_previous_owner = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for buyer != seller validation
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 && j + 10 < self.bytecode.len() { // CALLER
                            // Look for EQ check followed by REVERT (preventing same-address trading)
                            for k in (j + 1)..(j + 10).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 && k + 3 < self.bytecode.len() { // EQ
                                    if matches!(self.bytecode[k + 2], 0x57 | 0xfd) { // JUMPI/REVERT
                                        has_buyer_seller_check = true;
                                    }
                                }
                            }
                        }
                    }
                    
                    // Check for time-based cooling period (TIMESTAMP checks)
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 8 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j + 2] == 0x03 && self.bytecode[j + 4] == 0x11 { // SUB + GT
                                has_cooling_period = true;
                            }
                        }
                    }
                    
                    // Check for royalty/history tracking (multiple SLOAD operations)
                    let mut history_reads = 0;
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD
                            history_reads += 1;
                        }
                    }
                    if history_reads >= 3 {
                        has_royalty_tracking = true;
                    }
                    
                    // Check if reads previous owner data
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            // ownerOf selector (0x6352211e)
                            if self.bytecode[j + 1] == 0x63 {
                                checks_previous_owner = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if marketplace doesn't prevent wash trading
                return !has_buyer_seller_check || !has_cooling_period || !has_royalty_tracking || !checks_previous_owner;
            }
        }
        false
    }
}
