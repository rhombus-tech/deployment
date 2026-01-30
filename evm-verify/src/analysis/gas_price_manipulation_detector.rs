/// Gas Price Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct GasPriceManipulationDetector {
    bytecode: Vec<u8>,
}

impl GasPriceManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Gas price manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.82,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_gas_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_gas_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for logic dependent on gas price that can be manipulated
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // Functions that use gas price for critical decisions
            if matches!(self.bytecode[pos+1], 0x15 | 0x29 | 0x5a | 0x88) {
                let mut uses_gasprice = false;
                let mut lacks_gas_limit = false;
                let mut affects_payout = false;
                let mut enables_priority_manipulation = false;
                
                if pos + 55 < self.bytecode.len() {
                    // Check for GASPRICE opcode usage
                    for j in (pos + 5)..(pos + 25).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x3a { // GASPRICE
                            uses_gasprice = true;
                        }
                    }
                    
                    // Check if there's no upper bound on gas price
                    let mut has_gas_limit = false;
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x3a && j + 6 < self.bytecode.len() { // GASPRICE
                            if self.bytecode[j + 3] == 0x11 { // GT (checking limit)
                                has_gas_limit = true;
                            }
                        }
                    }
                    lacks_gas_limit = !has_gas_limit;
                    
                    // Check if gas price affects payouts/rewards
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x3a && j + 8 < self.bytecode.len() { // GASPRICE
                            if self.bytecode[j + 4] == 0x02 { // MUL (calculating payout)
                                affects_payout = true;
                            }
                        }
                    }
                    
                    // Check if priority can be manipulated via gas price
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x3a && j + 10 < self.bytecode.len() { // GASPRICE
                            if self.bytecode[j + 5] == 0x10 || self.bytecode[j + 5] == 0x11 { // LT/GT
                                enables_priority_manipulation = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if:
                // 1. Uses gas price for critical logic
                // 2. No upper bound on gas price
                // 3. Gas price affects financial outcomes
                // 4. Priority can be manipulated
                return uses_gasprice && (lacks_gas_limit || affects_payout || enables_priority_manipulation);
            }
        }
        false
    }
}
