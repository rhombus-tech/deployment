/// False Positive Tracker
/// Learns from user feedback to improve detection accuracy

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct FalsePositiveTracker {
    // Track false positive rate per detector
    detector_stats: HashMap<String, DetectorStats>,
    
    // Track specific patterns that are false positives
    known_false_positive_patterns: Vec<FalsePositivePattern>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DetectorStats {
    pub detector_name: String,
    pub total_findings: u32,
    pub confirmed_vulnerabilities: u32,
    pub false_positives: u32,
    pub false_positive_rate: f32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FalsePositivePattern {
    pub pattern_hash: String,
    pub bytecode_snippet: Vec<u8>,
    pub detector_name: String,
    pub occurrences: u32,
    pub confidence_penalty: f32,
}

impl FalsePositiveTracker {
    pub fn new() -> Self {
        Self {
            detector_stats: HashMap::new(),
            known_false_positive_patterns: Vec::new(),
        }
    }
    
    /// User confirms a finding is FALSE POSITIVE
    pub fn report_false_positive(
        &mut self,
        detector_name: &str,
        bytecode_snippet: Vec<u8>,
    ) {
        // Update detector stats
        let stats = self.detector_stats
            .entry(detector_name.to_string())
            .or_insert(DetectorStats {
                detector_name: detector_name.to_string(),
                total_findings: 0,
                confirmed_vulnerabilities: 0,
                false_positives: 0,
                false_positive_rate: 0.0,
            });
        
        stats.false_positives += 1;
        stats.total_findings += 1;
        stats.false_positive_rate = stats.false_positives as f32 / stats.total_findings as f32;
        
        // Record the specific pattern
        let pattern_hash = self.hash_pattern(&bytecode_snippet);
        
        if let Some(pattern) = self.known_false_positive_patterns
            .iter_mut()
            .find(|p| p.pattern_hash == pattern_hash) {
            
            pattern.occurrences += 1;
            // Increase penalty with each occurrence
            pattern.confidence_penalty = (pattern.occurrences as f32 * 0.1).min(0.95);
        } else {
            self.known_false_positive_patterns.push(FalsePositivePattern {
                pattern_hash,
                bytecode_snippet,
                detector_name: detector_name.to_string(),
                occurrences: 1,
                confidence_penalty: 0.2,
            });
        }
    }
    
    /// User confirms finding is REAL VULNERABILITY
    pub fn report_true_positive(&mut self, detector_name: &str) {
        let stats = self.detector_stats
            .entry(detector_name.to_string())
            .or_insert(DetectorStats {
                detector_name: detector_name.to_string(),
                total_findings: 0,
                confirmed_vulnerabilities: 0,
                false_positives: 0,
                false_positive_rate: 0.0,
            });
        
        stats.confirmed_vulnerabilities += 1;
        stats.total_findings += 1;
        stats.false_positive_rate = stats.false_positives as f32 / stats.total_findings as f32;
    }
    
    /// Check if pattern matches known false positive
    pub fn check_pattern(&self, bytecode: &[u8]) -> Option<f32> {
        for fp_pattern in &self.known_false_positive_patterns {
            if bytecode.windows(fp_pattern.bytecode_snippet.len())
                .any(|w| w == &fp_pattern.bytecode_snippet[..]) {
                
                return Some(fp_pattern.confidence_penalty);
            }
        }
        None
    }
    
    /// Get false positive rate for a detector
    pub fn get_detector_fp_rate(&self, detector_name: &str) -> f32 {
        self.detector_stats
            .get(detector_name)
            .map(|s| s.false_positive_rate)
            .unwrap_or(0.0)
    }
    
    /// Generate report
    pub fn generate_report(&self) -> String {
        let mut report = String::from("FALSE POSITIVE ANALYSIS\n");
        report.push_str("═══════════════════════════════════════\n\n");
        
        let mut detectors: Vec<_> = self.detector_stats.values().collect();
        detectors.sort_by(|a, b| {
            b.false_positive_rate.partial_cmp(&a.false_positive_rate).unwrap()
        });
        
        for stats in detectors {
            report.push_str(&format!(
                "{}: {:.1}% FP rate ({}/{} findings)\n",
                stats.detector_name,
                stats.false_positive_rate * 100.0,
                stats.false_positives,
                stats.total_findings
            ));
        }
        
        report.push_str(&format!(
            "\nKnown FP Patterns: {}\n",
            self.known_false_positive_patterns.len()
        ));
        
        report
    }
    
    fn hash_pattern(&self, bytecode: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        bytecode.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
    
    /// Save to file
    pub fn save(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    /// Load from file
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let json = std::fs::read_to_string(path)?;
        let tracker = serde_json::from_str(&json)?;
        Ok(tracker)
    }
}

impl Default for FalsePositiveTracker {
    fn default() -> Self {
        Self::new()
    }
}
