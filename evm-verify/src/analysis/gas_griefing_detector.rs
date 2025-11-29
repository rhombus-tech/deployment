// Gas Griefing / DOS Attack Detector
// Detects patterns that allow attackers to make functions unusable via gas exhaustion

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasGriefingVulnerability {
    pub vulnerability_type: GasGriefingType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub attack_cost: u128,
    pub dos_impact: DOSImpact,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GasGriefingType {
    UnboundedLoop,              // for(i=0; i<array.length; i++)
    UnboundedExternalCalls,     // Call N addresses in loop
    ExcessiveStorageWrites,     // Write to storage in loop
    BlockGasLimitExploit,       // Intentionally hit block gas limit
    RevertOnFailure,            // DOS via intentional revert
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DOSImpact {
    pub estimated_gas_cost: u64,
    pub functions_affected: Vec<String>,
    pub service_disruption: bool,
    pub fund_lock_risk: bool,
}

pub struct GasGriefingDetector {
    bytecode: Vec<u8>,
}

impl GasGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn analyze(&self) -> Vec<GasGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unbounded_loops());
        vulnerabilities.extend(self.detect_unbounded_external_calls());
        vulnerabilities.extend(self.detect_excessive_storage_writes());
        vulnerabilities.extend(self.detect_revert_dos());

        vulnerabilities
    }

    fn detect_unbounded_loops(&self) -> Vec<GasGriefingVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Loop with user-controlled iteration count
        // JUMPDEST, ..., CALLDATALOAD (user input), ..., JUMP/JUMPI (loop)
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x5B {  // JUMPDEST (loop start)
                // Check if loop bound comes from calldata (user-controlled)
                if self.has_calldata_in_range(i, i + 30) {
                    // Check if loop contains expensive operations
                    if self.has_expensive_ops_in_range(i, i + 50) {
                        vulns.push(GasGriefingVulnerability {
                            vulnerability_type: GasGriefingType::UnboundedLoop,
                            severity: SecuritySeverity::High,
                            description: "Loop with user-controlled iteration count - attacker can cause out-of-gas".to_string(),
                            attack_cost: 1_000_000_000_000_000u128, // 0.001 ETH to DOS
                            dos_impact: DOSImpact {
                                estimated_gas_cost: 30_000_000, // 30M gas
                                functions_affected: vec!["distribute".to_string(), "batchProcess".to_string()],
                                service_disruption: true,
                                fund_lock_risk: false,
                            },
                            remediation: "Add maximum iteration limit: require(recipients.length <= 100)".to_string(),
                        });
                    }
                }
            }
        }

        vulns
    }

    fn detect_unbounded_external_calls(&self) -> Vec<GasGriefingVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Loop with external CALL
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.is_loop_start(i) {
                // Check for CALL within loop
                if self.has_external_call_in_range(i, i + 60) {
                    vulns.push(GasGriefingVulnerability {
                        vulnerability_type: GasGriefingType::UnboundedExternalCalls,
                        severity: SecuritySeverity::Critical,
                        description: "External calls in unbounded loop - attacker can pass malicious contracts that consume all gas".to_string(),
                        attack_cost: 500_000_000_000_000u128, // 0.0005 ETH
                        dos_impact: DOSImpact {
                            estimated_gas_cost: 50_000_000,
                            functions_affected: vec!["airdrop".to_string(), "multiTransfer".to_string()],
                            service_disruption: true,
                            fund_lock_risk: true, // Funds can't be distributed
                        },
                        remediation: "1) Limit array size, 2) Use pull-over-push pattern, 3) Add gas limits to external calls".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn detect_excessive_storage_writes(&self) -> Vec<GasGriefingVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: SSTORE in loop (expensive)
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.is_loop_start(i) {
                // Count SSTORE operations in loop
                let sstore_count = self.count_sstore_in_range(i, i + 40);
                if sstore_count > 0 {
                    vulns.push(GasGriefingVulnerability {
                        vulnerability_type: GasGriefingType::ExcessiveStorageWrites,
                        severity: SecuritySeverity::Medium,
                        description: format!("Loop contains {} storage writes - high gas cost DOS vector", sstore_count),
                        attack_cost: 2_000_000_000_000_000u128,
                        dos_impact: DOSImpact {
                            estimated_gas_cost: 20_000 * sstore_count as u64, // 20K gas per SSTORE
                            functions_affected: vec!["updateAll".to_string()],
                            service_disruption: false,
                            fund_lock_risk: false,
                        },
                        remediation: "Consider batch updates or limit iteration count".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn detect_revert_dos(&self) -> Vec<GasGriefingVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: External call followed by REVERT if fails
        // Attacker can make their contract revert to DOS the function
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xF1 {  // CALL
                // Check if REVERT comes soon after (failure handling)
                if self.has_revert_after(i, 15) {
                    vulns.push(GasGriefingVulnerability {
                        vulnerability_type: GasGriefingType::RevertOnFailure,
                        severity: SecuritySeverity::Medium,
                        description: "Function reverts on failed external call - attacker can intentionally fail to DOS".to_string(),
                        attack_cost: 100_000_000_000_000u128,
                        dos_impact: DOSImpact {
                            estimated_gas_cost: 10_000_000,
                            functions_affected: vec!["claim".to_string(), "withdraw".to_string()],
                            service_disruption: true,
                            fund_lock_risk: true,
                        },
                        remediation: "Use try/catch or check return value without reverting".to_string(),
                    });
                }
            }
        }

        vulns
    }

    // === HELPER METHODS ===

    fn has_calldata_in_range(&self, start: usize, end: usize) -> bool {
        for i in start..end.min(self.bytecode.len()) {
            if self.bytecode[i] == 0x35 || self.bytecode[i] == 0x36 {  // CALLDATALOAD or CALLDATASIZE
                return true;
            }
        }
        false
    }

    fn has_expensive_ops_in_range(&self, start: usize, end: usize) -> bool {
        for i in start..end.min(self.bytecode.len()) {
            match self.bytecode[i] {
                0x55 | 0xF1 | 0xF2 | 0xF4 | 0x20 => return true,  // SSTORE, CALL, CALLCODE, DELEGATECALL, SHA3
                _ => {}
            }
        }
        false
    }

    fn is_loop_start(&self, offset: usize) -> bool {
        // JUMPDEST indicates potential loop
        offset < self.bytecode.len() && self.bytecode[offset] == 0x5B
    }

    fn has_external_call_in_range(&self, start: usize, end: usize) -> bool {
        for i in start..end.min(self.bytecode.len()) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xF2 || self.bytecode[i] == 0xF4 {
                return true;
            }
        }
        false
    }

    fn count_sstore_in_range(&self, start: usize, end: usize) -> usize {
        let mut count = 0;
        for i in start..end.min(self.bytecode.len()) {
            if self.bytecode[i] == 0x55 {
                count += 1;
            }
        }
        count
    }

    fn has_revert_after(&self, offset: usize, range: usize) -> bool {
        for i in offset..offset.saturating_add(range).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xFD {  // REVERT
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unbounded_loop_detection() {
        // Bytecode with loop using calldata
        let bytecode = vec![
            0x5B,  // JUMPDEST (loop start)
            0x35,  // CALLDATALOAD (user input)
            0x55,  // SSTORE (expensive op)
            0x56,  // JUMP (loop back)
        ];
        
        let detector = GasGriefingDetector::new(bytecode);
        let vulns = detector.detect_unbounded_loops();
        
        assert!(vulns.len() > 0, "Should detect unbounded loop");
    }

    #[test]
    fn test_external_call_in_loop() {
        let bytecode = vec![
            0x5B,  // JUMPDEST
            0xF1,  // CALL (external call in loop)
            0x56,  // JUMP
        ];
        
        let detector = GasGriefingDetector::new(bytecode);
        let vulns = detector.detect_unbounded_external_calls();
        
        assert!(vulns.len() > 0, "Should detect external call in loop");
    }
}
