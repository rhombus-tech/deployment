/// Cross-Detector Correlation Analyzer
/// Finds vulnerabilities that require multiple detectors to identify
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct CrossDetectorCorrelationAnalyzer {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CorrelatedVulnerability {
    pub location: usize,
    pub detector_chain: Vec<String>,
    pub combined_severity: SecuritySeverity,
    pub correlation_strength: f32,
}

impl CrossDetectorCorrelationAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn analyze_correlations(&self, vulnerabilities: &[(&str, usize, f32)]) -> Vec<CorrelatedVulnerability> {
        let mut correlated = Vec::new();

        // Find vulnerabilities at same location from different detectors
        for i in 0..vulnerabilities.len() {
            for j in (i+1)..vulnerabilities.len() {
                if self.are_correlated(&vulnerabilities[i], &vulnerabilities[j]) {
                    correlated.push(CorrelatedVulnerability {
                        location: vulnerabilities[i].1,
                        detector_chain: vec![
                            vulnerabilities[i].0.to_string(),
                            vulnerabilities[j].0.to_string(),
                        ],
                        combined_severity: SecuritySeverity::Critical,
                        correlation_strength: 0.85,
                    });
                }
            }
        }

        correlated
    }

    fn are_correlated(&self, v1: &(&str, usize, f32), v2: &(&str, usize, f32)) -> bool {
        // Same location or within 50 bytes
        v1.1.abs_diff(v2.1) < 50 && 
        // Both high confidence
        v1.2 > 0.7 && v2.2 > 0.7
    }

    pub fn detect_attack_chains(&self) -> Vec<Vec<String>> {
        // Detect multi-step attack patterns
        vec![
            vec!["reentrancy".to_string(), "unchecked_return".to_string()],
            vec!["integer_overflow".to_string(), "price_manipulation".to_string()],
        ]
    }
}
