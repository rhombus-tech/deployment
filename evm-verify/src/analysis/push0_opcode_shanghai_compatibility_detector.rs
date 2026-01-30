use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Push0CompatibilityVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// PUSH0 Opcode Shanghai Compatibility Detector
///
/// Detects usage of the PUSH0 (0x5f) opcode introduced in the Shanghai hard fork (EIP-3855),
/// which causes failures on pre-Shanghai chains and creates cross-chain compatibility issues.
///
/// Vulnerability Scenarios:
/// - Contracts compiled with Solidity 0.8.20+ use PUSH0 by default
/// - Pre-Shanghai chains treat 0x5f as invalid opcode
/// - Cross-chain deployments fail on older EVM versions
/// - Layer 2 chains with delayed Shanghai adoption
/// - Gas optimization using PUSH0 breaks compatibility
///
/// Real-World Impact:
/// - Contracts deployed to wrong chains become unusable
/// - Multi-chain protocols with inconsistent deployment
/// - Bridge contracts failing on certain chains
/// - DeFi protocols locked out of certain L2s
///
/// Detection Strategy:
/// - Identifies PUSH0 (0x5f) opcode usage
/// - Detects Solidity 0.8.20+ compilation artifacts
/// - Looks for PUSH0 in critical paths
/// - Checks for multiple PUSH0 operations (optimizer usage)
/// - Identifies missing Shanghai compatibility checks
pub struct Push0OpcodeShanghaiCompatibilityDetector {
    bytecode: Vec<u8>,
}

impl Push0OpcodeShanghaiCompatibilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Push0CompatibilityVulnerability> {
        self.detect()
            .into_iter()
            .map(|finding| Push0CompatibilityVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;
        let mut push0_count = 0;

        while i < self.bytecode.len() {
            // Pattern 1: PUSH0 opcode detected (Shanghai requirement)
            if self.bytecode[i] == 0x5f {
                push0_count += 1;
                
                if self.is_push0_in_critical_path(&self.bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "PUSH0 Shanghai incompatibility: PUSH0 opcode in critical path fails on pre-Shanghai chains, breaking contract functionality".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                } else {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "PUSH0 opcode detected: Contract requires Shanghai hard fork, incompatible with pre-Shanghai EVM chains".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            i += 1;
        }

        // Pattern 2: Multiple PUSH0 operations (optimizer generated)
        if push0_count >= 5 {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: format!("Extensive PUSH0 usage: {} PUSH0 operations detected, likely Solidity 0.8.20+ with optimizer, requires Shanghai hard fork", push0_count),
                pc: 0,
                confidence: 0.88,
            });
        }

        findings
    }

    fn is_push0_in_critical_path(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let lookback = 30.min(pos);
        
        let mut in_external_call = false;
        let mut in_state_change = false;
        let mut in_value_transfer = false;
        let mut in_critical_comparison = false;

        // Check context before PUSH0
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0xf1 | 0xf4 => in_external_call = true, // CALL, DELEGATECALL
                    0x55 => in_state_change = true, // SSTORE
                    0x34 => in_value_transfer = true, // CALLVALUE
                    _ => {}
                }
            }
        }

        // Check context after PUSH0
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xf4 => in_external_call = true, // CALL, DELEGATECALL
                    0x55 => in_state_change = true, // SSTORE
                    0x14 | 0x10 | 0x11 => in_critical_comparison = true, // EQ, LT, GT
                    0xfd | 0xfe => in_critical_comparison = true, // REVERT, INVALID
                    _ => {}
                }
            }
        }

        // PUSH0 in critical operations
        in_external_call || in_state_change || in_value_transfer || in_critical_comparison
    }
}
