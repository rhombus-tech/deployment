use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinningServiceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PinningServiceCentralizationRiskDetector {
    bytecode: Vec<u8>,
}

impl PinningServiceCentralizationRiskDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PinningServiceVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_single_provider_dependency());
        vulnerabilities.extend(self.detect_api_key_centralization());
        vulnerabilities.extend(self.detect_missing_redundancy_verification());

        vulnerabilities
    }

    fn detect_single_provider_dependency(&self) -> Vec<PinningServiceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut gateway_calls = 0;
        let mut unique_endpoints = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External calls to pinning services
            if matches!(opcode, 0xF1 | 0xFA) {
                gateway_calls += 1;
                
                // Check if there are different endpoint addresses nearby
                let start = if pc > 40 { pc - 40 } else { 0 };
                let window_end = (pc + 40).min(self.bytecode.len());
                let window = &self.bytecode[start..window_end];
                
                // Count unique address pushes (PUSH20 for addresses)
                if window.iter().filter(|&&b| b == 0x73).count() > 1 {
                    unique_endpoints += 1;
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // Single provider if multiple calls but no diversity
        if gateway_calls > 1 && unique_endpoints <= 1 {
            vulns.push(PinningServiceVulnerability {
                pc: 0,
                vulnerability_type: "SingleProviderDependency".to_string(),
                description: format!(
                    "Contract makes {} pinning service calls to single provider without fallback. \
                    Centralization risks: provider downtime causes complete data unavailability, \
                    censorship by single entity, terms-of-service changes affecting all pins, \
                    business failure impacts entire application. Missing: multi-provider pinning strategy, \
                    automatic failover mechanism, decentralized pin verification. Creates single point of failure.",
                    gateway_calls
                ),
                confidence: 0.89,
            });
        }

        vulns
    }

    fn detect_api_key_centralization(&self) -> Vec<PinningServiceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External calls with authentication
            if matches!(opcode, 0xF1 | 0xFA) {
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Look for hardcoded credentials (long PUSH operations before call)
                let has_long_push = window.iter().any(|&b| b >= 0x6C && b <= 0x7F); // PUSH13-PUSH32
                
                // Check for single authority control
                let window_end = (pc + 40).min(self.bytecode.len());
                let forward_window = &self.bytecode[pc..window_end];
                
                // Missing multi-sig or ownership rotation
                let has_owner_check = window.iter().any(|&b| b == 0x33); // CALLER
                let has_signature = window.iter().any(|&b| b == 0x01); // ECRECOVER
                
                if has_long_push && has_owner_check && !has_signature {
                    vulns.push(PinningServiceVulnerability {
                        pc,
                        vulnerability_type: "APIKeyCentralization".to_string(),
                        description: format!(
                            "Pinning service authentication at PC {} controlled by single owner without multi-sig. \
                            Vulnerable to: API key compromise, single admin control over all pins, \
                            inability to rotate credentials without contract upgrade. Missing: multi-sig authorization \
                            for pin operations, key rotation mechanism, decentralized access control. \
                            Single compromised key can delete all pinned content.",
                            pc
                        ),
                        confidence: 0.84,
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

    fn detect_missing_redundancy_verification(&self) -> Vec<PinningServiceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // SSTORE of content identifiers (CIDs)
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if storing hash/CID references
                let has_hash = window.windows(2).any(|w| w[0] == 0x60 && w[1] == 0x20); // PUSH1 32 (hash length)
                
                if has_hash {
                    // Check for redundancy validation
                    // Look for: multiple external calls, verification from different sources
                    let call_count = window.iter().filter(|&&b| matches!(b, 0xF1 | 0xFA)).count();
                    
                    // Check for availability verification
                    let has_verification = window.iter().any(|&b| b == 0x14); // EQ (checking return values)
                    
                    if call_count < 2 && !has_verification {
                        vulns.push(PinningServiceVulnerability {
                            pc,
                            vulnerability_type: "MissingRedundancyVerification".to_string(),
                            description: format!(
                                "Content pinning at PC {} without redundancy verification. \
                                Missing validation of: pin replication across multiple services, data availability \
                                from backup providers, automatic re-pinning on failure detection. Single pinning \
                                service failure causes: permanent data loss, broken application functionality, \
                                inability to recover content. Should verify pins on 2+ independent services.",
                                pc
                            ),
                            confidence: 0.80,
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
