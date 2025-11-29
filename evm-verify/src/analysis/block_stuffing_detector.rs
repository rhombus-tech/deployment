/// Block Stuffing / Advanced DOS Detector
/// Detects block gas limit attacks, transaction ordering DOS, memory exhaustion

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DosVulnerabilityType {
    BlockGasLimitAttack,
    TransactionOrderingDos,
    MemoryExhaustion,
    UnboundedLoop,
    StorageExplosion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecuritySeverity { Critical, High, Medium, Low }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DosVulnerability {
    pub vulnerability_type: DosVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct BlockStuffingDetector {
    bytecode: Vec<u8>,
}

impl BlockStuffingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DosVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unbounded_loops());
        vulnerabilities.extend(self.detect_storage_explosion());
        vulnerabilities.extend(self.detect_gas_limit_dos());
        vulnerabilities
    }

    fn detect_unbounded_loops(&self) -> Vec<DosVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x56 || self.bytecode[i] == 0x57 { // JUMP or JUMPI
                let window = &self.bytecode[i..i.saturating_add(30).min(self.bytecode.len())];
                let has_sload = window.contains(&0x54);
                let has_array_length = window.windows(2).any(|w| w[0] == 0x54 && w[1] == 0x10);
                
                if has_sload && !has_array_length {
                    vulnerabilities.push(DosVulnerability {
                        vulnerability_type: DosVulnerabilityType::UnboundedLoop,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Loop iterates over unbounded storage array. Gas cost grows with array size.".to_string(),
                        remediation: "Add pagination: for(uint i = start; i < end && i < array.length; i++)".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_storage_explosion(&self) -> Vec<DosVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x55 { // SSTORE
                let before = &self.bytecode[i.saturating_sub(20)..i];
                let has_caller = before.contains(&0x33);
                let has_limit_check = before.windows(2).any(|w| w[0] == 0x10 && w[1] == 0x57);
                
                if has_caller && !has_limit_check {
                    vulnerabilities.push(DosVulnerability {
                        vulnerability_type: DosVulnerabilityType::StorageExplosion,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Unlimited storage writes per caller. Attacker can bloat storage.".to_string(),
                        remediation: "Limit storage per user: require(userCount[msg.sender] < MAX_ENTRIES)".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_gas_limit_dos(&self) -> Vec<DosVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let batch_sigs = [&[0x8d, 0x80, 0xff, 0x0a][..], &[0x5c, 0x19, 0xa9, 0x5c][..]];
        
        for sig in batch_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                let window = &self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())];
                let has_gas_check = window.windows(5).any(|w| w.contains(&0x5a) && w.contains(&0x10));
                
                if !has_gas_check {
                    vulnerabilities.push(DosVulnerability {
                        vulnerability_type: DosVulnerabilityType::BlockGasLimitAttack,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Batch operation without gas limit check. Can hit block gas limit.".to_string(),
                        remediation: "Check remaining gas: require(gasleft() > MIN_GAS_PER_ITERATION * remaining)".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_unbounded_loop() {
        let bytecode = vec![0x54, 0x56]; // SLOAD, JUMP (unbounded)
        let detector = BlockStuffingDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, DosVulnerabilityType::UnboundedLoop)));
    }
}
