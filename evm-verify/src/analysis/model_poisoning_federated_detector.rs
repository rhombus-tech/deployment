// Model Poisoning & Federated Learning Attack Detector
// Detects vulnerabilities in federated learning and collaborative ML systems

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ModelPoisoningVulnerability {
    // Byzantine attack in federated system
    ByzantineAttackRisk {
        pc: usize,
        aggregation_point: Vec<u8>,
        malicious_threshold: f64,
        description: String,
    },
    
    // Training data poisoning
    TrainingDataPoisoning {
        pc: usize,
        data_submission: Vec<u8>,
        validation_gap: String,
        description: String,
    },
    
    // Gradient manipulation
    GradientManipulation {
        pc: usize,
        gradient_update: Vec<u8>,
        manipulation_vector: String,
        description: String,
    },
    
    // Model extraction through queries
    ModelExtractionRisk {
        pc: usize,
        query_pattern: Vec<u8>,
        extraction_feasibility: f64,
        description: String,
    },
    
    // Backdoor injection
    BackdoorInjection {
        pc: usize,
        trigger_pattern: Vec<u8>,
        injection_method: String,
        description: String,
    },
    
    // Membership inference on training data
    TrainingDataLeakage {
        pc: usize,
        confidence_exposure: Vec<u8>,
        leakage_severity: f64,
        description: String,
    },
}

pub struct ModelPoisoningFederatedDetector {
    bytecode: Vec<u8>,
}

impl ModelPoisoningFederatedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ModelPoisoningVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_byzantine_attacks());
        vulnerabilities.extend(self.detect_data_poisoning());
        vulnerabilities.extend(self.detect_gradient_manipulation());
        vulnerabilities.extend(self.detect_model_extraction());
        vulnerabilities.extend(self.detect_backdoor_injection());
        vulnerabilities.extend(self.detect_training_data_leakage());

        vulnerabilities
    }

    fn detect_byzantine_attacks(&self) -> Vec<ModelPoisoningVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect model aggregation without Byzantine fault tolerance
        while i < self.bytecode.len() {
            if i + 40 < self.bytecode.len() {
                // Multiple SLOAD operations suggesting model weight aggregation
                let mut sload_count = 0;
                let mut has_median_aggregation = false;
                let mut has_outlier_detection = false;
                
                for j in i..(i + 40).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // SLOAD
                        sload_count += 1;
                    }
                    // DIV followed by complex arithmetic (median calculation)
                    if self.bytecode[j] == 0x04 && j + 5 < self.bytecode.len() {
                        if self.bytecode[j + 1] == 0x10 || self.bytecode[j + 1] == 0x11 {
                            has_median_aggregation = true;
                        }
                    }
                    // Standard deviation check pattern
                    if self.bytecode[j] == 0x0a && self.bytecode.get(j + 1) == Some(&0x04) {
                        has_outlier_detection = true;
                    }
                }

                // Simple averaging without outlier removal
                if sload_count >= 3 && !has_median_aggregation && !has_outlier_detection {
                    vulns.push(ModelPoisoningVulnerability::ByzantineAttackRisk {
                        pc: i,
                        aggregation_point: self.bytecode[i..i.saturating_add(40).min(self.bytecode.len())].to_vec(),
                        malicious_threshold: 0.33,
                        description: format!(
                            "Byzantine attack risk at PC {}: Model weight aggregation uses simple averaging \
                            without Byzantine fault tolerance. Attacker controlling >33% of nodes can poison \
                            the global model. Implement Krum, trimmed mean, or median-based aggregation.",
                            i
                        ),
                    });
                }
            }
            i += 1;
        }

        vulns
    }

    fn detect_data_poisoning(&self) -> Vec<ModelPoisoningVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect unvalidated training data submission
        while i < self.bytecode.len() {
            if i + 30 < self.bytecode.len() {
                // CALLDATACOPY followed by SSTORE (data submission)
                if self.bytecode[i] == 0x37 {
                    let mut has_data_validation = false;
                    let mut stores_data = false;
                    
                    for j in (i + 1)..(i + 30).min(self.bytecode.len()) {
                        // Statistical validation (rare patterns)
                        if self.bytecode[j] == 0x20 { // SHA3 for data hashing
                            has_data_validation = true;
                        }
                        // SSTORE
                        if self.bytecode[j] == 0x55 {
                            stores_data = true;
                        }
                    }

                    if stores_data && !has_data_validation {
                        vulns.push(ModelPoisoningVulnerability::TrainingDataPoisoning {
                            pc: i,
                            data_submission: self.bytecode[i..i.saturating_add(30).min(self.bytecode.len())].to_vec(),
                            validation_gap: "no_statistical_checks".to_string(),
                            description: format!(
                                "Training data poisoning risk at PC {}: User-submitted training data stored \
                                without validation. Attacker can submit mislabeled or adversarial data to corrupt \
                                the model. Add data sanitization, outlier detection, and label verification.",
                                i
                            ),
                        });
                    }
                }
            }
            i += 1;
        }

        vulns
    }

    fn detect_gradient_manipulation(&self) -> Vec<ModelPoisoningVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect gradient update without validation
        while i < self.bytecode.len() {
            if i + 35 < self.bytecode.len() {
                // Multiple ADD/SUB operations suggesting gradient updates
                let mut arithmetic_ops = 0;
                let mut has_gradient_clipping = false;
                let mut has_norm_check = false;
                
                for j in i..(i + 35).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 || self.bytecode[j] == 0x03 {
                        arithmetic_ops += 1;
                    }
                    // Gradient clipping (comparison + conditional update)
                    if (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) 
                        && j + 2 < self.bytecode.len()
                        && self.bytecode[j + 1] == 0x57 { // JUMPI
                        has_gradient_clipping = true;
                    }
                    // Norm calculation (MUL + ADD + DIV pattern)
                    if self.bytecode[j] == 0x02 
                        && j + 3 < self.bytecode.len()
                        && self.bytecode[j + 2] == 0x04 {
                        has_norm_check = true;
                    }
                }

                if arithmetic_ops >= 5 && !has_gradient_clipping && !has_norm_check {
                    vulns.push(ModelPoisoningVulnerability::GradientManipulation {
                        pc: i,
                        gradient_update: self.bytecode[i..i.saturating_add(35).min(self.bytecode.len())].to_vec(),
                        manipulation_vector: "unbounded_gradients".to_string(),
                        description: format!(
                            "Gradient manipulation at PC {}: Model updates without gradient clipping or norm checks. \
                            Attacker can submit extreme gradients to corrupt model or cause divergence. \
                            Implement gradient clipping, norm-based validation, and differential privacy.",
                            i
                        ),
                    });
                }
            }
            i += 1;
        }

        vulns
    }

    fn detect_model_extraction(&self) -> Vec<ModelPoisoningVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect unlimited query access enabling model extraction
        while i < self.bytecode.len() {
            if i + 25 < self.bytecode.len() {
                // STATICCALL to model inference
                if self.bytecode[i] == 0xfa {
                    let mut has_query_limit = false;
                    let mut has_query_cost = false;
                    
                    // Check for rate limiting
                    for j in (i.saturating_sub(15))..(i + 15).min(self.bytecode.len()) {
                        // SLOAD + timestamp check
                        if self.bytecode[j] == 0x54 && j + 3 < self.bytecode.len() {
                            if self.bytecode[j + 2] == 0x42 { // TIMESTAMP
                                has_query_limit = true;
                            }
                        }
                        // CALLVALUE check (payment required)
                        if self.bytecode[j] == 0x34 && self.bytecode.get(j + 1) == Some(&0x10) {
                            has_query_cost = true;
                        }
                    }

                    if !has_query_limit && !has_query_cost {
                        vulns.push(ModelPoisoningVulnerability::ModelExtractionRisk {
                            pc: i,
                            query_pattern: self.bytecode[i..i.saturating_add(25).min(self.bytecode.len())].to_vec(),
                            extraction_feasibility: 0.90,
                            description: format!(
                                "Model extraction risk at PC {}: Unlimited free queries allow attacker to extract \
                                model by querying with strategically chosen inputs. Implement per-address query \
                                limits, query costs, or add noise to outputs to prevent extraction.",
                                i
                            ),
                        });
                    }
                }
            }
            i += 1;
        }

        vulns
    }

    fn detect_backdoor_injection(&self) -> Vec<ModelPoisoningVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect model update patterns vulnerable to backdoor injection
        while i < self.bytecode.len() {
            if i + 45 < self.bytecode.len() {
                // Pattern: CALLDATACOPY + multiple SSTORE (model weight update)
                if self.bytecode[i] == 0x37 {
                    let mut sstore_count = 0;
                    let mut has_trigger_detection = false;
                    
                    for j in (i + 1)..(i + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE
                            sstore_count += 1;
                        }
                        // Anomaly detection pattern (complex)
                        if self.bytecode[j] == 0x20 && j + 5 < self.bytecode.len() {
                            if self.bytecode[j + 3] == 0x10 {
                                has_trigger_detection = true;
                            }
                        }
                    }

                    // Multiple weight updates without backdoor detection
                    if sstore_count >= 5 && !has_trigger_detection {
                        vulns.push(ModelPoisoningVulnerability::BackdoorInjection {
                            pc: i,
                            trigger_pattern: self.bytecode[i..i.saturating_add(45).min(self.bytecode.len())].to_vec(),
                            injection_method: "weight_manipulation".to_string(),
                            description: format!(
                                "Backdoor injection risk at PC {}: Model weights updated without backdoor \
                                trigger detection. Attacker can inject backdoors that activate on specific inputs. \
                                Implement activation clustering analysis and trigger input detection.",
                                i
                            ),
                        });
                    }
                }
            }
            i += 1;
        }

        vulns
    }

    fn detect_training_data_leakage(&self) -> Vec<ModelPoisoningVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect patterns where training data can be inferred from model
        while i < self.bytecode.len() {
            if i + 20 < self.bytecode.len() {
                // RETURNDATACOPY followed by LOG (exposing model outputs)
                if self.bytecode[i] == 0x3e {
                    let mut logs_predictions = false;
                    let mut logs_confidence = false;
                    
                    for j in (i + 1)..(i + 20).min(self.bytecode.len()) {
                        if self.bytecode[j] >= 0xa0 && self.bytecode[j] <= 0xa4 {
                            logs_predictions = true;
                            // Check if confidence scores are logged
                            if j + 10 < self.bytecode.len() {
                                logs_confidence = true;
                            }
                        }
                    }

                    if logs_predictions && logs_confidence {
                        vulns.push(ModelPoisoningVulnerability::TrainingDataLeakage {
                            pc: i,
                            confidence_exposure: self.bytecode[i..i.saturating_add(20).min(self.bytecode.len())].to_vec(),
                            leakage_severity: 0.78,
                            description: format!(
                                "Training data leakage at PC {}: Detailed prediction confidence scores enable \
                                membership inference attacks to determine if data was in training set. \
                                Apply differential privacy, round confidence scores, or limit output precision.",
                                i
                            ),
                        });
                    }
                }
            }
            i += 1;
        }

        vulns
    }
}
