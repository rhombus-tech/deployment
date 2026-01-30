// Adversarial Input ML Oracle Attack Detector
// Detects vulnerabilities to adversarial examples in ML oracle integrations

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum AdversarialMLVulnerability {
    // Gradient-based adversarial attacks
    GradientBasedManipulation {
        pc: usize,
        oracle_call: Vec<u8>,
        input_sensitivity: f64,
        description: String,
    },
    
    // Model inversion attacks
    ModelInversionRisk {
        pc: usize,
        output_leakage: Vec<u8>,
        training_data_exposure: f64,
        description: String,
    },
    
    // Membership inference attacks
    MembershipInference {
        pc: usize,
        confidence_leak: Vec<u8>,
        inference_risk: f64,
        description: String,
    },
    
    // Adversarial example vulnerability
    AdversarialExampleExploitable {
        pc: usize,
        input_validation_gap: Vec<u8>,
        perturbation_threshold: f64,
        description: String,
    },
    
    // Oracle output manipulation
    OracleOutputManipulation {
        pc: usize,
        prediction_manipulation: Vec<u8>,
        confidence_exploitation: f64,
        description: String,
    },
    
    // Feature space exploitation
    FeatureSpaceExploit {
        pc: usize,
        feature_engineering_gap: Vec<u8>,
        exploitation_vector: String,
        description: String,
    },
    
    // Evasion attack surface
    EvasionAttackSurface {
        pc: usize,
        evasion_technique: String,
        success_probability: f64,
        description: String,
    },
}

pub struct AdversarialInputMLDetector {
    bytecode: Vec<u8>,
}

impl AdversarialInputMLDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AdversarialMLVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect gradient-based manipulation
        vulnerabilities.extend(self.detect_gradient_manipulation());
        
        // Detect model inversion risks
        vulnerabilities.extend(self.detect_model_inversion());
        
        // Detect membership inference
        vulnerabilities.extend(self.detect_membership_inference());
        
        // Detect adversarial examples
        vulnerabilities.extend(self.detect_adversarial_examples());
        
        // Detect oracle manipulation
        vulnerabilities.extend(self.detect_oracle_manipulation());
        
        // Detect feature space exploits
        vulnerabilities.extend(self.detect_feature_space_exploits());
        
        // Detect evasion attack surfaces
        vulnerabilities.extend(self.detect_evasion_attacks());

        vulnerabilities
    }

    fn detect_gradient_manipulation(&self) -> Vec<AdversarialMLVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // ML oracle call patterns (STATICCALL to oracle, followed by input processing)
        while i < self.bytecode.len() {
            if i + 10 < self.bytecode.len() {
                // STATICCALL (0xfa) to external oracle
                if self.bytecode[i] == 0xfa {
                    // Check for lack of input bounds checking
                    let mut has_bounds_check = false;
                    let mut has_gradient_defense = false;
                    
                    // Look ahead for validation patterns
                    for j in (i + 1)..(i + 50).min(self.bytecode.len()) {
                        // GT/LT checks on inputs
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {
                            has_bounds_check = true;
                        }
                        // REVERT on validation failure
                        if self.bytecode[j] == 0xfd && has_bounds_check {
                            has_gradient_defense = true;
                        }
                    }

                    if !has_gradient_defense {
                        vulns.push(AdversarialMLVulnerability::GradientBasedManipulation {
                            pc: i,
                            oracle_call: self.bytecode[i..i.saturating_add(10).min(self.bytecode.len())].to_vec(),
                            input_sensitivity: 0.85,
                            description: format!(
                                "ML oracle call at PC {} lacks gradient-based adversarial input defenses. \
                                Attacker can craft inputs with small perturbations that cause misclassification. \
                                CRITICAL: Add input sanitization, bounds checking, and anomaly detection before oracle calls.",
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

    fn detect_model_inversion(&self) -> Vec<AdversarialMLVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect patterns where model outputs leak training data
        while i < self.bytecode.len() {
            if i + 20 < self.bytecode.len() {
                // CALL/STATICCALL followed by RETURNDATASIZE and RETURNDATACOPY
                if (self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa) 
                    && i + 15 < self.bytecode.len() {
                    
                    let has_returndatasize = self.bytecode[i..i + 15].contains(&0x3d);
                    let has_returndatacopy = self.bytecode[i..i + 15].contains(&0x3e);
                    
                    // Check if confidence scores are exposed
                    let mut exposes_confidence = false;
                    for j in (i + 1)..(i + 20).min(self.bytecode.len()) {
                        // LOG events exposing outputs
                        if self.bytecode[j] >= 0xa0 && self.bytecode[j] <= 0xa4 {
                            exposes_confidence = true;
                        }
                    }

                    if has_returndatasize && has_returndatacopy && exposes_confidence {
                        vulns.push(AdversarialMLVulnerability::ModelInversionRisk {
                            pc: i,
                            output_leakage: self.bytecode[i..i.saturating_add(20).min(self.bytecode.len())].to_vec(),
                            training_data_exposure: 0.75,
                            description: format!(
                                "Model inversion risk at PC {}: ML model outputs expose confidence scores \
                                that can be used to infer training data. Attacker can query the model repeatedly \
                                to reconstruct sensitive training examples. Add output obfuscation and rate limiting.",
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

    fn detect_membership_inference(&self) -> Vec<AdversarialMLVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect patterns vulnerable to membership inference attacks
        while i < self.bytecode.len() {
            if i + 15 < self.bytecode.len() {
                // Oracle call returning detailed predictions
                if self.bytecode[i] == 0xfa {
                    let mut high_confidence_exposed = false;
                    let mut no_differential_privacy = true;
                    
                    // Check for confidence threshold filtering
                    for j in (i + 1)..(i + 15).min(self.bytecode.len()) {
                        // Multiple comparisons suggesting confidence levels
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {
                            high_confidence_exposed = true;
                        }
                        // Noise addition patterns (rare in bytecode)
                        if self.bytecode[j] == 0x03 && self.bytecode[j + 1] == 0x06 {
                            no_differential_privacy = false;
                        }
                    }

                    if high_confidence_exposed && no_differential_privacy {
                        vulns.push(AdversarialMLVulnerability::MembershipInference {
                            pc: i,
                            confidence_leak: self.bytecode[i..i.saturating_add(15).min(self.bytecode.len())].to_vec(),
                            inference_risk: 0.80,
                            description: format!(
                                "Membership inference vulnerability at PC {}: Model confidence scores \
                                allow attacker to determine if specific data was in training set. \
                                Implement differential privacy, add noise to outputs, or use prediction thresholds.",
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

    fn detect_adversarial_examples(&self) -> Vec<AdversarialMLVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect lack of adversarial robustness checks
        while i < self.bytecode.len() {
            if i + 25 < self.bytecode.len() {
                // CALLDATALOAD followed by direct oracle call
                if self.bytecode[i] == 0x35 {
                    let mut has_sanitization = false;
                    let mut has_oracle_call = false;
                    
                    for j in (i + 1)..(i + 25).min(self.bytecode.len()) {
                        // Check for input sanitization (hashing, normalization)
                        if self.bytecode[j] == 0x20 { // SHA3
                            has_sanitization = true;
                        }
                        // Oracle call
                        if self.bytecode[j] == 0xfa || self.bytecode[j] == 0xf1 {
                            has_oracle_call = true;
                        }
                    }

                    if has_oracle_call && !has_sanitization {
                        vulns.push(AdversarialMLVulnerability::AdversarialExampleExploitable {
                            pc: i,
                            input_validation_gap: self.bytecode[i..i.saturating_add(25).min(self.bytecode.len())].to_vec(),
                            perturbation_threshold: 0.01,
                            description: format!(
                                "Adversarial example vulnerability at PC {}: User input passed directly to ML oracle \
                                without sanitization. Attacker can craft inputs with imperceptible perturbations \
                                that cause misclassification. Add input preprocessing and adversarial detection.",
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

    fn detect_oracle_manipulation(&self) -> Vec<AdversarialMLVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect oracle output manipulation vulnerabilities
        while i < self.bytecode.len() {
            if i + 20 < self.bytecode.len() {
                // RETURNDATACOPY followed by critical decision
                if self.bytecode[i] == 0x3e {
                    let mut has_output_validation = false;
                    let mut makes_critical_decision = false;
                    
                    for j in (i + 1)..(i + 20).min(self.bytecode.len()) {
                        // Range checks on oracle output
                        if (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) 
                            && self.bytecode[j + 1] == 0x15 {
                            has_output_validation = true;
                        }
                        // CALL/SELFDESTRUCT (critical operations)
                        if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0xff {
                            makes_critical_decision = true;
                        }
                    }

                    if makes_critical_decision && !has_output_validation {
                        vulns.push(AdversarialMLVulnerability::OracleOutputManipulation {
                            pc: i,
                            prediction_manipulation: self.bytecode[i..i.saturating_add(20).min(self.bytecode.len())].to_vec(),
                            confidence_exploitation: 0.88,
                            description: format!(
                                "Oracle output manipulation at PC {}: ML prediction used for critical decision \
                                without validation. Attacker can manipulate inputs to control oracle output. \
                                Add output range checks, multiple oracle consensus, and sanity checks.",
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

    fn detect_feature_space_exploits(&self) -> Vec<AdversarialMLVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect feature engineering gaps
        while i < self.bytecode.len() {
            if i + 30 < self.bytecode.len() {
                // Multiple CALLDATALOAD suggesting feature extraction
                let mut feature_count = 0;
                let mut has_feature_validation = false;
                
                for j in i..(i + 30).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x35 {
                        feature_count += 1;
                    }
                    // Feature correlation checks (complex patterns)
                    if self.bytecode[j] == 0x02 && self.bytecode[j + 1] == 0x04 {
                        has_feature_validation = true;
                    }
                }

                if feature_count >= 3 && !has_feature_validation {
                    vulns.push(AdversarialMLVulnerability::FeatureSpaceExploit {
                        pc: i,
                        feature_engineering_gap: self.bytecode[i..i.saturating_add(30).min(self.bytecode.len())].to_vec(),
                        exploitation_vector: "uncorrelated_features".to_string(),
                        description: format!(
                            "Feature space exploitation at PC {}: Multiple features extracted without \
                            correlation validation. Attacker can provide statistically impossible feature \
                            combinations that exploit model blind spots. Add feature correlation checks.",
                            i
                        ),
                    });
                }
            }
            i += 1;
        }

        vulns
    }

    fn detect_evasion_attacks(&self) -> Vec<AdversarialMLVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        // Detect evasion attack surfaces
        while i < self.bytecode.len() {
            if i + 18 < self.bytecode.len() {
                // CALL to ML oracle with no rate limiting
                if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa {
                    let mut has_rate_limit = false;
                    let mut has_query_tracking = false;
                    
                    // Look for SLOAD (state read for rate limiting)
                    for j in (i.saturating_sub(10))..(i + 10).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 {
                            has_query_tracking = true;
                        }
                        // Timestamp comparison
                        if self.bytecode[j] == 0x42 && self.bytecode[j + 1] == 0x10 {
                            has_rate_limit = true;
                        }
                    }

                    if !has_rate_limit && !has_query_tracking {
                        vulns.push(AdversarialMLVulnerability::EvasionAttackSurface {
                            pc: i,
                            evasion_technique: "unlimited_queries".to_string(),
                            success_probability: 0.92,
                            description: format!(
                                "Evasion attack surface at PC {}: Unlimited ML oracle queries allow attacker \
                                to probe model boundaries and craft evasion attacks. Implement per-address \
                                rate limiting and query cost to prevent model extraction.",
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
