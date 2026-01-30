use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlModelPoisoningVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct OnChainMlModelPoisoningDetector {
    bytecode: Vec<u8>,
}

impl OnChainMlModelPoisoningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MlModelPoisoningVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unvalidated_weight_updates());
        vulnerabilities.extend(self.detect_training_data_injection());
        vulnerabilities.extend(self.detect_gradient_manipulation());

        vulnerabilities
    }

    fn detect_unvalidated_weight_updates(&self) -> Vec<MlModelPoisoningVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (model weight update)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_weight_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_arithmetic = window.iter().any(|&b| matches!(b, 0x01 | 0x02 | 0x03)); // ADD, MUL, SUB
                
                if has_weight_data && has_arithmetic {
                    let has_bounds_check = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_signature = window.iter().any(|&b| b == 0x01); // ECRECOVER
                    let has_aggregation = window.iter().any(|&b| b == 0x04); // DIV (averaging)
                    
                    if !has_bounds_check || !has_signature || !has_aggregation {
                        vulns.push(MlModelPoisoningVulnerability {
                            pc,
                            vulnerability_type: "UnvalidatedWeightUpdates".to_string(),
                            description: format!(
                                "ML model weight update at PC {} accepts unvalidated participant submissions. Poisoning attack: \
                                malicious participant submits extreme weight values, corrupting model to produce desired outputs. \
                                Example: prediction market ML model poisoned to favor specific outcomes. Missing: weight bounds \
                                validation, participant reputation weighting, outlier detection, Byzantine-robust aggregation. \
                                Single malicious update can compromise model integrity.",
                                pc
                            ),
                            confidence: 0.88,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_training_data_injection(&self) -> Vec<MlModelPoisoningVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (training data storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_data_input = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_data_input {
                    let has_data_validation = window.iter().any(|&b| b == 0x20); // KECCAK256 (data integrity)
                    let has_source_verification = window.iter().any(|&b| b == 0x33); // CALLER
                    let has_data_sanitization = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    
                    if !has_data_validation || !has_source_verification || !has_data_sanitization {
                        vulns.push(MlModelPoisoningVulnerability {
                            pc,
                            vulnerability_type: "TrainingDataInjection".to_string(),
                            description: format!(
                                "Training data submission at PC {} without poisoning protection. Data poisoning: attacker \
                                contributes mislabeled or adversarial examples to training set, biasing model behavior. \
                                Example: spam classifier trained with spam labeled as legitimate. Missing: data provenance \
                                verification, label validation, outlier detection, data quality scoring. Enables targeted \
                                model manipulation through poisoned training data.",
                                pc
                            ),
                            confidence: 0.86,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_gradient_manipulation(&self) -> Vec<MlModelPoisoningVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 || opcode == 0x04 { // MUL, DIV (gradient computation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_gradient_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_model_weight = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_gradient_data && has_model_weight {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_norm_check = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT (gradient clipping)
                    let has_sign_verification = forward.iter().any(|&b| b == 0x19); // NOT (checking sign)
                    
                    if !has_norm_check || !has_sign_verification {
                        vulns.push(MlModelPoisoningVulnerability {
                            pc,
                            vulnerability_type: "GradientManipulation".to_string(),
                            description: format!(
                                "Gradient computation at PC {} vulnerable to Byzantine gradient attacks. Attack: malicious \
                                participant submits gradients with extreme magnitudes or inverted signs, causing model divergence \
                                or targeted misbehavior. Missing: gradient norm clipping, sign consistency validation, \
                                median-based aggregation. Enables model poisoning via gradient manipulation in federated learning.",
                                pc
                            ),
                            confidence: 0.84,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
