use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderingFalsificationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct RenderingTaskResultFalsificationDetector {
    bytecode: Vec<u8>,
}

impl RenderingTaskResultFalsificationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RenderingFalsificationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_output_hash_manipulation());
        vulnerabilities.extend(self.detect_quality_verification_bypass());
        vulnerabilities.extend(self.detect_partial_rendering_fraud());

        vulnerabilities
    }

    fn detect_output_hash_manipulation(&self) -> Vec<RenderingFalsificationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (output hash)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_output_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_output_data {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_payment = forward.iter().any(|&b| matches!(b, 0xF1 | 0x55)); // CALL, SSTORE
                    
                    if has_payment {
                        let has_input_verification = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                        let has_preimage_availability = forward.iter().any(|&b| matches!(b, 0xF1 | 0xFA));
                        
                        if !has_input_verification || !has_preimage_availability {
                            vulns.push(RenderingFalsificationVulnerability {
                                pc,
                                vulnerability_type: "OutputHashManipulation".to_string(),
                                description: format!(
                                    "Rendering output hash at PC {} accepted without verifying actual output. Worker can submit \
                                    hash of garbage data and claim payment. Attack: compute hash of random bytes, submit without \
                                    rendering. Missing: input parameters hash check, output preimage availability verification, \
                                    spot-check random frame verification. Hash provides no guarantee work was performed.",
                                    pc
                                ),
                                confidence: 0.87,
                            });
                        }
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

    fn detect_quality_verification_bypass(&self) -> Vec<RenderingFalsificationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (accepting render result)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_result_submission = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_result_submission {
                    let has_quality_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT (quality metric)
                    let has_sample_verification = window.iter().filter(|&&b| b == 0x20).count() >= 2; // Multiple hashes
                    let has_oracle_validation = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA)); // External validator
                    
                    if !has_quality_check && !has_sample_verification && !has_oracle_validation {
                        vulns.push(RenderingFalsificationVulnerability {
                            pc,
                            vulnerability_type: "QualityVerificationBypass".to_string(),
                            description: format!(
                                "Render result acceptance at PC {} without quality validation. Worker can submit low-quality or \
                                corrupted renders. Example: submit black frames, blurry output, incomplete rendering. Missing: \
                                quality metrics validation, sample frame verification, ML-based quality oracle. No mechanism ensures \
                                output meets requirements. Should verify resolution, completeness, visual quality.",
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

    fn detect_partial_rendering_fraud(&self) -> Vec<RenderingFalsificationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (frame range submission)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_frame_count = window.iter().any(|&b| matches!(b, 0x01 | 0x03)); // ADD, SUB (counting)
                let has_payment = window.iter().any(|&b| matches!(b, 0xF1 | 0x02)); // CALL or MUL (payment calc)
                
                if has_frame_count && has_payment {
                    let has_completeness_check = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ
                    let has_sequential_verification = window.iter().any(|&b| b == 0x54); // SLOAD (checking previous frames)
                    
                    if !has_completeness_check || !has_sequential_verification {
                        vulns.push(RenderingFalsificationVulnerability {
                            pc,
                            vulnerability_type: "PartialRenderingFraud".to_string(),
                            description: format!(
                                "Partial rendering submission at PC {} without completeness validation. Worker can claim payment for \
                                full job while submitting partial results. Attack: render frames 1-100, skip 101-200, submit claiming \
                                200 frames complete. Missing: frame sequence verification, gap detection, total frame count validation. \
                                Enables payment theft by skipping difficult/time-consuming frames.",
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
