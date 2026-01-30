use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerAnalysisGasCorrelationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PowerAnalysisGasConsumptionCorrelationDetector {
    bytecode: Vec<u8>,
}

impl PowerAnalysisGasConsumptionCorrelationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PowerAnalysisGasCorrelationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_hamming_weight_correlation());
        vulnerabilities.extend(self.detect_differential_power_leakage());
        vulnerabilities.extend(self.detect_operation_dependent_gas_pattern());
        vulnerabilities
    }

    fn detect_hamming_weight_correlation(&self) -> Vec<PowerAnalysisGasCorrelationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x02 { // MUL (cryptographic operation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let operates_on_secret = self.bytecode[start..pc].iter().any(|&b| b == 0x54);
                if operates_on_secret {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let has_blinding = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x03).count() >= 2;
                    if !has_blinding {
                        vulns.push(PowerAnalysisGasCorrelationVulnerability {
                            pc,
                            vulnerability_type: "HammingWeightCorrelation".to_string(),
                            description: format!("Cryptographic operation at PC {} has gas consumption correlated with secret Hamming weight. Attack: gas cost of operations varies with number of 1-bits in operands, attacker measures gas for many known plaintexts, correlates with gas consumption, performs DPA to extract key bits where correlation highest. Real attack: AES S-box lookup gas cost proportional to Hamming weight of key XOR plaintext, 1000 measurements with correlation analysis reveals key byte. Example: modular exponentiation gas varies with number of 1s in exponent, attacker measures gas for random messages, statistical correlation reveals exponent bits. Missing: constant-gas operations, blinding. Should implement: multiply-and-add both possible values, select result, or add random blinding. Fix: for each bit operation, perform dummy operation if bit=0 to equalize gas, or use additive blinding: compute on (secret + random) then subtract random from result.", pc),
                            confidence: 0.77,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_differential_power_leakage(&self) -> Vec<PowerAnalysisGasCorrelationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (hash operation on secret)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let inputs_from_secret = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 1;
                if inputs_from_secret {
                    let has_masking = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x16 | 0x17 | 0x18)).count() >= 2;
                    if !has_masking {
                        vulns.push(PowerAnalysisGasCorrelationVulnerability {
                            pc,
                            vulnerability_type: "DifferentialPowerLeakage".to_string(),
                            description: format!("Hash operation at PC {} on secret data enables differential power analysis. Attack: attacker collects gas traces for many inputs, computes differential of gas consumption between two input sets differing in one bit, correlation reveals secret bit values at that position. Real attack: SHA3(secretKey || nonce), collect 10000 traces, divide into sets where input_bit[i]=0 vs =1, compute average gas difference, significant difference at position i reveals secretKey[i]. Example: HMAC verification H(key || message), attacker varies message bits, measures gas, differential analysis extracts key as gas varies with key⊕message Hamming distance. Missing: first-order DPA resistance, masking. Should implement: boolean masking where secret split into shares, operate on shares separately. Fix: split secret into s = s1 ⊕ s2, compute H(s1 || nonce1) and H(s2 || nonce2) separately, combine results, ensure intermediate values don't correlate with secret.", pc),
                            confidence: 0.74,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_operation_dependent_gas_pattern(&self) -> Vec<PowerAnalysisGasCorrelationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x05 { // MOD (used in cryptographic operations)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let part_of_crypto = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x02 | 0x04 | 0x09)).count() >= 2;
                if part_of_crypto {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let has_uniform_cost = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x02).count() >= 2;
                    if !has_uniform_cost {
                        vulns.push(PowerAnalysisGasCorrelationVulnerability {
                            pc,
                            vulnerability_type: "OperationDependentGasPattern".to_string(),
                            description: format!("Modular arithmetic at PC {} has operation-dependent gas pattern revealing secret structure. Attack: sequence of MUL/MOD operations for modular exponentiation, gas pattern reveals which operations performed, leaks exponent bit pattern, reduces key search space. Real vulnerability: square-and-multiply exponentiation, if(exp_bit) {{ result = mul(result, base); }}, presence/absence of MUL reveals bit, attacker reconstructs exponent from gas trace. Example: RSA signature with exponent d, gas trace shows MUL operations at positions [1,3,5,7,9], reveals d has 1-bits at those positions, eliminates 2^(256-5) possible keys. Missing: constant-time exponentiation, Montgomery ladder. Should implement: always multiply, use conditional selection, or Montgomery ladder doing multiply+square every iteration. Fix: for each exponent bit, perform both square and multiply, select result based on bit: result = bit ? (result*base) : result, ensure selection has constant gas.", pc),
                            confidence: 0.81,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
