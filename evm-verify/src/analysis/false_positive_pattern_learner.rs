/// False Positive Pattern Learner
/// Meta-validator that learns which detector patterns produce false positives
use std::collections::HashMap;
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct FalsePositivePatternLearner {
    bytecode: Vec<u8>,
    known_fp_patterns: HashMap<String, f32>,
}

#[derive(Debug, Clone)]
pub struct FalsePositiveSignature {
    pub pattern_hash: String,
    pub detector_name: String,
    pub fp_probability: f32,
}

impl FalsePositivePatternLearner {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { 
            bytecode,
            known_fp_patterns: Self::load_known_patterns(),
        }
    }

    fn load_known_patterns() -> HashMap<String, f32> {
        let mut patterns = HashMap::new();
        
        // Common false positive patterns
        patterns.insert("SafeMath_overflow".to_string(), 0.15); // SafeMath properly used
        patterns.insert("Ownable_centralization".to_string(), 0.20); // Intended admin control
        patterns.insert("View_reentrancy".to_string(), 0.90); // View functions can't reenter
        
        patterns
    }

    pub fn is_likely_false_positive(&self, detector: &str, location: usize) -> bool {
        // Check if matches known FP pattern
        let pattern_key = format!("{}_{}", detector, self.extract_pattern_at(location));
        
        if let Some(&fp_rate) = self.known_fp_patterns.get(&pattern_key) {
            fp_rate > 0.5
        } else {
            false
        }
    }

    fn extract_pattern_at(&self, location: usize) -> String {
        // Extract bytecode pattern around location
        let window = self.bytecode.get(location..location.saturating_add(10)).unwrap_or(&[]);
        format!("{:?}", window)
    }

    pub fn learn_from_feedback(&mut self, detector: &str, was_fp: bool) {
        let key = format!("{}_pattern", detector);
        let entry = self.known_fp_patterns.entry(key).or_insert(0.5);
        
        // Update probability using Bayesian update
        if was_fp {
            *entry = (*entry + 0.1).min(1.0);
        } else {
            *entry = (*entry - 0.1).max(0.0);
        }
    }
}
