/// Spark Protocol (MakerDAO D3M) Detector
/// Detects vulnerabilities in Spark <-> Maker integrations
/// Critical for: Spark Protocol D3M lending

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparkProtocolVulnerability {
    pub vulnerability_type: SparkProtocolIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SparkProtocolIssueType {
    D3MRiskExposure,               // D3M Direct Deposit Module risk
    SparkMakerIntegrationExploit,  // Integration vulnerability
    SDAIYieldManipulation,         // sDAI yield exploit
    CapacityCeilingBypass,         // Capacity limit circumvention
    OracleDependencyRisk,          // Oracle dependency on Maker
}

pub struct SparkProtocolDetector {
    bytecode: Vec<u8>,
}

impl SparkProtocolDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SparkProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_spark_integration() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_d3m_risks());
        vulnerabilities.extend(self.detect_capacity_issues());

        vulnerabilities
    }

    fn detect_d3m_risks(&self) -> Vec<SparkProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.interacts_with_d3m(i) && !self.validates_d3m_limits(i) {
                vulnerabilities.push(SparkProtocolVulnerability {
                    vulnerability_type: SparkProtocolIssueType::D3MRiskExposure,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "D3M interaction without proper limit validation".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract interacts with MakerDAO D3M\n\
                        2. No validation of D3M debt ceiling\n\
                        3. Excessive borrowing from Maker\n\
                        4. Risk concentration in Spark protocol\n\n\
                        Fix: Validate D3M limits before operations",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_capacity_issues(&self) -> Vec<SparkProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.modifies_capacity(i) && !self.enforces_ceiling(i) {
                vulnerabilities.push(SparkProtocolVulnerability {
                    vulnerability_type: SparkProtocolIssueType::CapacityCeilingBypass,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: "Capacity modification without ceiling enforcement".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Spark capacity ceiling should limit deposits\n\
                        2. No enforcement of maximum capacity\n\
                        3. Over-utilization of Maker liquidity\n\
                        4. Systemic risk if Maker oracle fails\n\n\
                        Fix: Enforce strict capacity ceilings",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn is_spark_integration(&self) -> bool {
        let spark_sig = [0x8e, 0x19, 0x89, 0x9e]; // Spark-specific function
        self.bytecode.windows(4).any(|w| w == spark_sig)
    }

    fn interacts_with_d3m(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len() && self.bytecode[pos] == 0xF1 // CALL
    }

    fn validates_d3m_limits(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {
                return true;
            }
        }
        false
    }

    fn modifies_capacity(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len() && self.bytecode[pos] == 0x55 // SSTORE
    }

    fn enforces_ceiling(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(20)..pos {
            if self.bytecode[i] == 0x10 {
                return true;
            }
        }
        false
    }
}
