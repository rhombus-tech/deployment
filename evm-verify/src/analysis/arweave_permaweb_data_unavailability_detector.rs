use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArweaveVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ArweavePermawebDataUnavailabilityDetector {
    bytecode: Vec<u8>,
}

impl ArweavePermawebDataUnavailabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ArweaveVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_data_availability_check());
        vulnerabilities.extend(self.detect_single_gateway_dependency());
        vulnerabilities.extend(self.detect_transaction_id_manipulation());

        vulnerabilities
    }

    fn detect_missing_data_availability_check(&self) -> Vec<ArweaveVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External call (CALL/STATICCALL) followed by immediate storage without verification
            if matches!(opcode, 0xF1 | 0xFA) {
                let mut check_pc = pc + 1;
                let mut found_sstore = false;
                let mut has_revert = false;
                let mut instructions = 0;

                while check_pc < self.bytecode.len() && instructions < 30 {
                    let check_op = self.bytecode[check_pc];
                    
                    if check_op == 0x55 { // SSTORE
                        found_sstore = true;
                        break;
                    }
                    
                    if matches!(check_op, 0xFD | 0xFE) { // REVERT, INVALID
                        has_revert = true;
                    }
                    
                    check_pc += 1;
                    instructions += 1;
                    
                    if check_op >= 0x60 && check_op <= 0x7F {
                        check_pc += (check_op - 0x5F) as usize;
                    }
                }

                if found_sstore && !has_revert {
                    vulns.push(ArweaveVulnerability {
                        pc,
                        vulnerability_type: "MissingDataAvailabilityCheck".to_string(),
                        description: format!(
                            "Arweave data reference stored at PC {} without availability verification. \
                            Transaction may be pending, data may not be permanently stored yet, or \
                            gateway may be unreachable. Missing confirmation checks for data permanence.",
                            pc
                        ),
                        confidence: 0.87,
                    });
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_single_gateway_dependency(&self) -> Vec<ArweaveVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut gateway_calls = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for external calls that might be to Arweave gateways
            if matches!(opcode, 0xF1 | 0xFA) {
                gateway_calls += 1;
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // If only 1-2 gateway calls found, likely single point of failure
        if gateway_calls > 0 && gateway_calls <= 2 {
            vulns.push(ArweaveVulnerability {
                pc: 0,
                vulnerability_type: "SingleGatewayDependency".to_string(),
                description: format!(
                    "Contract has {} Arweave gateway call(s) without fallback mechanisms. \
                    Single gateway dependency creates centralization risk. If gateway is down, \
                    censors content, or rate-limits requests, data becomes unavailable. \
                    Recommend multi-gateway strategy with automatic failover.",
                    gateway_calls
                ),
                confidence: 0.82,
            });
        }

        vulns
    }

    fn detect_transaction_id_manipulation(&self) -> Vec<ArweaveVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // SSTORE with hash-like data but no signature verification
            if opcode == 0x55 {
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for 32-byte hash patterns (Arweave TX IDs)
                let has_hash = window.windows(2).any(|w| w[0] == 0x60 && w[1] == 0x20);
                
                // Missing signature verification (no ECRECOVER or cryptographic checks)
                let has_sig_check = window.iter().any(|&b| b == 0x01); // ECRECOVER precompile
                
                if has_hash && !has_sig_check {
                    vulns.push(ArweaveVulnerability {
                        pc,
                        vulnerability_type: "TransactionIDManipulation".to_string(),
                        description: format!(
                            "Arweave transaction ID stored at PC {} without signature verification. \
                            Attacker can provide fake TX IDs pointing to non-existent or malicious data. \
                            Missing cryptographic proof that data was actually uploaded to Arweave network.",
                            pc
                        ),
                        confidence: 0.85,
                    });
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
