use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOpAggregationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct UserOperationSignatureAggregationDosDetector {
    bytecode: Vec<u8>,
}

impl UserOperationSignatureAggregationDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<UserOpAggregationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unbounded_aggregation_batch());
        vulnerabilities.extend(self.detect_malicious_signature_injection());
        vulnerabilities.extend(self.detect_aggregator_censorship_risk());

        vulnerabilities
    }

    fn detect_unbounded_aggregation_batch(&self) -> Vec<UserOpAggregationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for loop patterns (JUMPI for batch processing)
            if opcode == 0x57 { // JUMPI
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for array length/counter (CALLDATALOAD or SLOAD)
                let has_length_load = window.iter().any(|&b| matches!(b, 0x35 | 0x54));
                
                // Check for signature verification in loop (ECRECOVER or bn256 pairing)
                let has_sig_verify = window.iter().any(|&b| matches!(b, 0x01 | 0x08)); // ECRECOVER, bn256Pairing
                
                if has_length_load && has_sig_verify {
                    // Check for batch size limit
                    let has_limit_check = window.iter().enumerate().any(|(i, &b)| {
                        b == 0x10 && i + 1 < window.len() && window[i + 1] == 0x57 // LT + JUMPI
                    });
                    
                    if !has_limit_check {
                        vulns.push(UserOpAggregationVulnerability {
                            pc,
                            vulnerability_type: "UnboundedAggregationBatch".to_string(),
                            description: format!(
                                "ERC-4337 signature aggregator at PC {} processes unbounded batch size. \
                                DoS attack: submit bundle with thousands of UserOps, aggregator runs out of gas \
                                during verification, entire bundle fails. Missing: maximum batch size enforcement, \
                                gas limit per signature check, incremental validation. Bundler can be griefed by \
                                forcing expensive signature aggregation that exceeds block gas limit.",
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

    fn detect_malicious_signature_injection(&self) -> Vec<UserOpAggregationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for aggregated signature validation
            if opcode == 0x08 { // bn256Pairing (BLS aggregation common pattern)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for signature input reading
                let has_calldata = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_calldata {
                    // Check for signature integrity validation
                    let has_hash_check = window.iter().any(|&b| b == 0x20); // KECCAK256
                    let has_length_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    // Check for individual signature extraction and verification
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    let has_revert_on_invalid = forward_window.iter().any(|&b| b == 0xFD);
                    
                    if !has_hash_check && !has_length_check && has_revert_on_invalid {
                        vulns.push(UserOpAggregationVulnerability {
                            pc,
                            vulnerability_type: "MaliciousSignatureInjection".to_string(),
                            description: format!(
                                "Signature aggregation at PC {} vulnerable to malicious signature injection. \
                                Attack vector: aggregator includes invalid/malicious signatures in batch, causing \
                                entire bundle validation to fail, censoring legitimate UserOps. Missing validation: \
                                individual signature pre-check, aggregation integrity proof, signature origin authentication. \
                                Malicious aggregator can selectively DoS users by including poison signatures.",
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

    fn detect_aggregator_censorship_risk(&self) -> Vec<UserOpAggregationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for aggregator selection/approval logic
            if opcode == 0x33 { // CALLER (checking aggregator address)
                let window_end = (pc + 70).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for aggregator whitelist (SLOAD + EQ pattern)
                let has_whitelist = window.windows(2).any(|w| w[0] == 0x54 && w[1] == 0x14);
                
                if has_whitelist {
                    // Check for aggregator rotation/fallback mechanism
                    let has_alternative = window.iter().filter(|&&b| b == 0x57).count() > 1; // Multiple JUMPI (branching)
                    
                    // Check for time-based rotation
                    let has_timestamp = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_alternative && !has_timestamp {
                        vulns.push(UserOpAggregationVulnerability {
                            pc,
                            vulnerability_type: "AggregatorCensorshipRisk".to_string(),
                            description: format!(
                                "Aggregator approval at PC {} creates single point of censorship. \
                                Centralization risk: whitelisted aggregator can selectively exclude UserOps, \
                                censoring specific users/applications. Missing: multi-aggregator support, \
                                automatic fallback to non-aggregated mode, aggregator rotation mechanism. \
                                Compromised/malicious aggregator has complete power to censor transactions \
                                without alternative execution path.",
                                pc
                            ),
                            confidence: 0.81,
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
