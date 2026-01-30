use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversarialInputVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct NeuralNetworkAdversarialInputDetector {
    bytecode: Vec<u8>,
}

impl NeuralNetworkAdversarialInputDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<AdversarialInputVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_input_sanitization());
        vulnerabilities.extend(self.detect_confidence_threshold_bypass());
        vulnerabilities.extend(self.detect_adversarial_perturbation_resistance());

        vulnerabilities
    }

    fn detect_missing_input_sanitization(&self) -> Vec<AdversarialInputVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (inference input)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_computation = window.iter().any(|&b| matches!(b, 0x02 | 0x04)); // MUL, DIV (NN computation)
                let has_external_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xF4)); // Model inference call
                
                if has_computation || has_external_call {
                    let has_range_validation = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_normalization = window.iter().any(|&b| b == 0x04); // DIV (input normalization)
                    let has_bounds_clipping = window.iter().any(|&b| b == 0xFD); // REVERT on invalid
                    
                    if !has_range_validation || !has_normalization || !has_bounds_clipping {
                        vulns.push(AdversarialInputVulnerability {
                            pc,
                            vulnerability_type: "MissingInputSanitization".to_string(),
                            description: format!(
                                "Neural network input at PC {} lacks adversarial input protection. Adversarial examples: \
                                carefully crafted inputs cause misclassification. Example: image classifier sees stop sign as \
                                speed limit via pixel perturbation. Missing: input range validation, normalization, adversarial \
                                detection layer. Enables manipulation of on-chain ML predictions through adversarial inputs.",
                                pc
                            ),
                            confidence: 0.85,
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

    fn detect_confidence_threshold_bypass(&self) -> Vec<AdversarialInputVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xFA) { // Model inference call
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_result_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                
                if has_result_check {
                    let has_confidence_score = window.iter().any(|&b| b == 0x04); // DIV (probability calculation)
                    let has_threshold = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_uncertainty_measure = window.iter().any(|&b| b == 0x03); // SUB (variance)
                    
                    if !has_confidence_score || !has_threshold || !has_uncertainty_measure {
                        vulns.push(AdversarialInputVulnerability {
                            pc,
                            vulnerability_type: "ConfidenceThresholdBypass".to_string(),
                            description: format!(
                                "Model inference at PC {} uses predictions without confidence validation. Attack: adversarial \
                                examples often have high confidence on wrong class. Missing confidence threshold causes accepting \
                                high-confidence misclassifications. Missing: minimum confidence requirement, uncertainty quantification, \
                                prediction rejection mechanism. Adversarial inputs bypass safety through manipulated confidence scores.",
                                pc
                            ),
                            confidence: 0.87,
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

    fn detect_adversarial_perturbation_resistance(&self) -> Vec<AdversarialInputVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (input data)
                let window_end = (pc + 120).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_inference = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA)); // Model call
                
                if has_inference {
                    let has_multiple_predictions = window.iter().filter(|&&b| matches!(b, 0xF1 | 0xFA)).count() >= 2;
                    let has_ensemble = window.iter().any(|&b| b == 0x04); // DIV (ensemble averaging)
                    let has_consistency_check = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ
                    
                    if !has_multiple_predictions || !has_ensemble || !has_consistency_check {
                        vulns.push(AdversarialInputVulnerability {
                            pc,
                            vulnerability_type: "AdversarialPerturbationResistance".to_string(),
                            description: format!(
                                "Single model inference at PC {} vulnerable to adversarial perturbations. Defense: ensemble \
                                methods and input transformations increase robustness. Missing: model ensemble (multiple models \
                                vote), input transformation randomization, consistency validation across predictions. Single \
                                model easily fooled by targeted adversarial examples. Should use 3+ diverse models for robustness.",
                                pc
                            ),
                            confidence: 0.83,
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
