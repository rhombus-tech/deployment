/// Poly Network 2021 Exploit Detector
use crate::bytecode::SecurityFinding;

pub struct PolyNetwork2021Detector {
    bytecode: Vec<u8>,
}

impl PolyNetwork2021Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Poly Network-style privilege escalation at PC {}", location),
                pc: location,
                confidence: 0.91,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_keeper_replacement(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_keeper_replacement(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for keeper/owner address update from external call data
        if self.bytecode[pos] == 0x55 { // SSTORE
            if pos > 30 {
                let mut loads_calldata = false;
                let mut has_auth_check = false;
                
                for j in pos.saturating_sub(30)..pos {
                    if j >= self.bytecode.len() { break; }
                    // CALLDATALOAD (user input)
                    if self.bytecode[j] == 0x35 {
                        loads_calldata = true;
                    }
                    // Authorization check (CALLER comparison or onlyOwner)
                    if self.bytecode[j] == 0x33 { // CALLER
                        if j + 10 < self.bytecode.len() {
                            for k in (j + 1)..(j + 10).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 { // EQ
                                    has_auth_check = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                
                // Vulnerable if stores calldata without proper auth
                return loads_calldata && !has_auth_check;
            }
        }
        false
    }
}
