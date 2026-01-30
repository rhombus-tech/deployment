use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct SiloIsolatedMarketCrossContaminationDetector {
    bytecode: Vec<u8>,
}

impl SiloIsolatedMarketCrossContaminationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_silo_isolation_breach() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Isolated market silos can be cross-contaminated through shared state or oracle manipulation, causing cascading failures across supposedly isolated markets.".to_string(),
                pc,
                confidence: 0.92,
            });
        }

        if let Some(pc) = self.detect_cross_silo_oracle_pollution() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Oracle data can leak between isolated silos, allowing manipulation in one silo to affect pricing in others.".to_string(),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_silo_isolation_breach(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut shared_storage_access = 0;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x54 { // SLOAD
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x54 {
                        shared_storage_access += 1;
                    }
                    if bytecode[j] == 0x55 && shared_storage_access > 0 {
                        return Some(i);
                    }
                }
            }
        }

        None
    }

    fn detect_cross_silo_oracle_pollution(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut oracle_calls = 0;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (oracle)
                oracle_calls += 1;
                
                if oracle_calls >= 2 {
                    for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                        if bytecode[j] == 0x55 { // SSTORE (shared state)
                            return Some(i);
                        }
                    }
                }
            }
        }

        None
    }
}
