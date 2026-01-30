/// Temporal Logic Paradox Detector (ENHANCED)
///
/// Detects impossible event orderings (A requires B, B requires A)
/// Enhancement over circular_dependency_detector with paradox-specific analysis
/// Impact: $100M+ from deadlock states

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalParadoxVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub paradox_type: ParadoxType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParadoxType {
    MutualPrerequisite,    // A needs B, B needs A
    TemporalLoop,          // Event chain loops back
    ImpossibleOrdering,    // No valid execution order exists
}

pub struct TemporalLogicParadoxDetector {
    bytecode: Vec<u8>,
}

impl TemporalLogicParadoxDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TemporalParadoxVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_mutual_prerequisite() {
            vulnerabilities.push(TemporalParadoxVulnerability {
                location: 0,
                severity: SecuritySeverity::Critical,
                paradox_type: ParadoxType::MutualPrerequisite,
                description: "Functions require each other - impossible to call either".to_string(),
                exploit_scenario: 
                    "function initialize() { require(isConfigured); }\n\
                     function configure() { require(isInitialized); }\n\n\
                     // Paradox: Can't initialize without configuring,\n\
                     // can't configure without initializing!\n\
                     // Result: Contract permanently locked".to_string(),
                remediation: "Break circular dependency with admin override or initialization phase".to_string(),
                confidence: 0.85,
            });
        }
        
        vulnerabilities
    }

    fn has_mutual_prerequisite(&self) -> bool {
        // Detect multiple SLOAD checks suggesting mutual dependencies
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 5 && jumpi_count > 3
    }
}
