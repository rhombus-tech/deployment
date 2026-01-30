/// Detector Confidence Calibrator
/// Meta-validator that calibrates confidence scores based on historical accuracy
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct DetectorConfidenceCalibrator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ConfidenceCalibration {
    pub detector_name: String,
    pub raw_confidence: f32,
    pub calibrated_confidence: f32,
    pub historical_accuracy: f32,
}

impl DetectorConfidenceCalibrator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn calibrate_detector_confidence(&self, detector_name: &str, raw_confidence: f32) -> f32 {
        // Calibrate based on detector's historical false positive rate
        let calibration_factor = self.get_calibration_factor(detector_name);
        (raw_confidence * calibration_factor).min(1.0).max(0.0)
    }

    fn get_calibration_factor(&self, detector_name: &str) -> f32 {
        // Known high-accuracy detectors get boost, others get penalty
        match detector_name {
            name if name.contains("reentrancy") => 0.95,
            name if name.contains("integer_overflow") => 0.90,
            name if name.contains("unchecked") => 0.92,
            _ => 0.85, // Conservative default
        }
    }

    pub fn should_suppress_finding(&self, confidence: f32, severity: &SecuritySeverity) -> bool {
        // Suppress low-confidence findings based on severity
        match severity {
            SecuritySeverity::Critical => confidence < 0.70,
            SecuritySeverity::High => confidence < 0.60,
            _ => confidence < 0.50,
        }
    }
}
