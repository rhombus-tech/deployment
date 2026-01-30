use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMeasurementVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ComputeResourceMeasurementCheatingDetector {
    bytecode: Vec<u8>,
}

impl ComputeResourceMeasurementCheatingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ResourceMeasurementVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_self_reported_metrics());
        vulnerabilities.extend(self.detect_computation_time_inflation());
        vulnerabilities.extend(self.detect_benchmark_gaming());

        vulnerabilities
    }

    fn detect_self_reported_metrics(&self) -> Vec<ResourceMeasurementVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (resource metrics submission)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_cpu_time = window.iter().any(|&b| matches!(b, 0x01 | 0x02)); // ADD, MUL (time calc)
                let has_payment = window.iter().any(|&b| matches!(b, 0xF1 | 0x55)); // CALL, SSTORE
                
                if has_cpu_time && has_payment {
                    let has_verification = window.iter().any(|&b| b == 0x01); // ECRECOVER (attestation)
                    let has_benchmark_comparison = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_tee_proof = window.iter().any(|&b| b == 0x08); // bn256Pairing (TEE attestation)
                    
                    if !has_verification || !has_benchmark_comparison || !has_tee_proof {
                        vulns.push(ResourceMeasurementVulnerability {
                            pc,
                            vulnerability_type: "SelfReportedMetrics".to_string(),
                            description: format!(
                                "Resource metrics at PC {} based on self-reporting without verification. Worker can inflate \
                                computation time/resources to receive higher payment. Attack: report 10 hours for 1-minute job. \
                                Missing: TEE attestation of execution time, benchmark-based validation, verifiable timing proofs. \
                                Should use trusted execution environment or deterministic benchmarks.",
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

    fn detect_computation_time_inflation(&self) -> Vec<ResourceMeasurementVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (timing measurement)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let window_end = (pc + 80).min(self.bytecode.len());
                let forward = &self.bytecode[pc..window_end];
                
                let has_time_delta = forward.iter().any(|&b| b == 0x03); // SUB (elapsed time)
                let has_payment_calc = forward.iter().any(|&b| b == 0x02); // MUL (payment based on time)
                
                if has_time_delta && has_payment_calc {
                    let has_maximum_time = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_result_verification = forward.iter().any(|&b| b == 0x20); // KECCAK256
                    
                    if !has_maximum_time || !has_result_verification {
                        vulns.push(ResourceMeasurementVulnerability {
                            pc,
                            vulnerability_type: "ComputationTimeInflation".to_string(),
                            description: format!(
                                "Computation time payment at PC {} without bounds or correctness check. Worker can artificially \
                                delay completion to increase payment. Attack: sleep between computations, claim extended time. \
                                Missing: maximum time limit, result correctness verification showing work was done, expected time \
                                baseline. Time-based payment requires proving time was spent computing, not idle.",
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

    fn detect_benchmark_gaming(&self) -> Vec<ResourceMeasurementVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (storing worker capability)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_benchmark_score = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_score_calc = window.iter().any(|&b| matches!(b, 0x02 | 0x04)); // MUL, DIV
                
                if has_benchmark_score && has_score_calc {
                    let has_random_challenge = window.iter().any(|&b| b == 0x40); // BLOCKHASH (randomness)
                    let has_multiple_tests = window.iter().filter(|&&b| b == 0x35).count() >= 3;
                    let has_time_constraint = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_random_challenge || !has_multiple_tests || !has_time_constraint {
                        vulns.push(ResourceMeasurementVulnerability {
                            pc,
                            vulnerability_type: "BenchmarkGaming".to_string(),
                            description: format!(
                                "Benchmark score at PC {} vulnerable to gaming. Worker can optimize for known benchmarks while \
                                underperforming on actual work. Attack: detect benchmark pattern, use cached results or specialized \
                                code path. Missing: randomized benchmark selection, multiple diverse tests, time limits preventing \
                                pre-computation. Should use unpredictable challenges requiring general capability.",
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
