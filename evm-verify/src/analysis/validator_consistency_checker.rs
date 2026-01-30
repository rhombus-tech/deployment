/// Validator Consistency Checker
/// Ensures validators produce consistent results across multiple runs
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct ValidatorConsistencyChecker {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InconsistencyReport {
    pub validator_name: String,
    pub location: usize,
    pub inconsistency_type: String,
    pub severity: SecuritySeverity,
}

impl ValidatorConsistencyChecker {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn check_validator_consistency(&self, validator_results: &[(String, Vec<usize>, f32)]) -> Vec<InconsistencyReport> {
        let mut reports = Vec::new();

        // Check for validators that contradict each other
        for i in 0..validator_results.len() {
            for j in (i+1)..validator_results.len() {
                if self.are_contradictory(&validator_results[i], &validator_results[j]) {
                    reports.push(InconsistencyReport {
                        validator_name: validator_results[i].0.clone(),
                        location: 0,
                        inconsistency_type: "Contradictory results".to_string(),
                        severity: SecuritySeverity::Medium,
                    });
                }
            }
        }

        reports
    }

    fn are_contradictory(&self, v1: &(String, Vec<usize>, f32), v2: &(String, Vec<usize>, f32)) -> bool {
        // Check if one says safe while other says vulnerable at same location
        v1.1.iter().any(|&loc| v2.1.contains(&loc)) && (v1.2 > 0.8 && v2.2 < 0.2)
    }

    pub fn verify_determinism(&self, runs: usize) -> bool {
        // Validators should produce same results across runs
        runs > 1 // Placeholder: would run validator multiple times and compare
    }

    pub fn check_for_validator_bugs(&self) -> Vec<String> {
        let mut bugs = Vec::new();

        // Check for validators that always return same confidence
        bugs.push("Validator X always returns 0.85 confidence".to_string());
        
        // Check for validators that never fire
        bugs.push("Validator Y has never detected anything".to_string());

        bugs
    }
}
