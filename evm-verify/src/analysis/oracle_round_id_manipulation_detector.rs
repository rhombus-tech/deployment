/// Oracle Round ID Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct OracleRoundIdManipulationDetector {
    bytecode: Vec<u8>,
}

impl OracleRoundIdManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Oracle round ID manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.84,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_round_id_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_round_id_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for oracle round ID usage that can be manipulated
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // getRoundData, historicalRoundData, latestRound selectors
            if matches!(self.bytecode[pos+1], 0x9a | 0xb6 | 0xd8 | 0xfc) {
                let mut validates_round_completeness = false;
                let mut checks_round_sequencing = false;
                let mut prevents_round_reorg = false;
                let mut validates_round_freshness = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for round completeness validation
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x15 && j + 3 < self.bytecode.len() { // ISZERO
                            // Should check answered in round is set
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                validates_round_completeness = true;
                            }
                        }
                    }
                    
                    // Check for round sequencing (monotonic increase)
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 { // GT (checking round ID increases)
                            checks_round_sequencing = true;
                        }
                    }
                    
                    // Check for round reorganization prevention
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x14 && j + 6 < self.bytecode.len() { // EQ
                            // Should verify round ID matches answered in round
                            if self.bytecode[j + 3] == 0x15 { // ISZERO (mismatch check)
                                prevents_round_reorg = true;
                            }
                        }
                    }
                    
                    // Check for round freshness (not too old)
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 8 < self.bytecode.len() { // SLOAD
                            // Should check last used round ID
                            if self.bytecode[j + 5] == 0x10 { // LT (checking not outdated)
                                validates_round_freshness = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if round IDs can be manipulated via:
                // 1. Round completeness not validated
                // 2. Round sequencing not checked
                // 3. Round reorganizations possible
                // 4. Stale round IDs accepted
                return !validates_round_completeness || !checks_round_sequencing || !prevents_round_reorg || !validates_round_freshness;
            }
        }
        false
    }
}
