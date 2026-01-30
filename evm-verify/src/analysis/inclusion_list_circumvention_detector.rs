use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionListCircumventionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct InclusionListCircumventionDetector {
    bytecode: Vec<u8>,
}

impl InclusionListCircumventionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<InclusionListCircumventionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Inclusion lists force transaction inclusion but can be circumvented
        // Detect insufficient inclusion list enforcement
        if let Some(location) = self.has_weak_inclusion_enforcement() {
            vulnerabilities.push(InclusionListCircumventionVulnerability {
                vulnerability_type: "Weak Inclusion List Enforcement".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Inclusion list transactions not validated against actual block contents. Proposers can claim inclusion without executing transactions. Implement cryptographic proof of inclusion.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect inclusion list ordering manipulation
        if let Some(location) = self.has_inclusion_ordering_manipulation() {
            vulnerabilities.push(InclusionListCircumventionVulnerability {
                vulnerability_type: "Inclusion List Ordering Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Inclusion list lacks ordering enforcement. Proposers can reorder transactions to extract MEV while technically including all mandated transactions. Implement strict FIFO ordering for inclusion list.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect inclusion list censorship via gas manipulation
        if let Some(location) = self.has_gas_limit_censorship() {
            vulnerabilities.push(InclusionListCircumventionVulnerability {
                vulnerability_type: "Inclusion List Gas Limit Censorship".to_string(),
                location,
                severity: "High".to_string(),
                description: "Inclusion list transactions executed with insufficient gas. Proposers can censor by forcing out-of-gas failures while claiming compliance. Validate minimum gas allocation per inclusion transaction.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_weak_inclusion_enforcement(&self) -> Option<usize> {
        // Pattern: Inclusion claim without verification
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for inclusion list reference (storage read of required txs)
            if self.bytecode[i] == 0x54 { // SLOAD (inclusion list)
                // Check if inclusion is verified cryptographically
                let mut has_crypto_verification = false;
                
                for j in i+1..i+35.min(self.bytecode.len()) {
                    // Look for merkle proof or signature verification
                    if self.bytecode[j] == 0x20 { // SHA3 (merkle proof)
                        // Check if compared against root
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (root comparison)
                                has_crypto_verification = true;
                                break;
                            }
                        }
                    }
                    // Or ECRECOVER for signature
                    if self.bytecode[j] == 0xfa { // STATICCALL
                        // Check if calling ecrecover (address 0x01)
                        for k in j.saturating_sub(10)..j {
                            if self.bytecode[k] == 0x60 { // PUSH1
                                if k + 1 < self.bytecode.len() && self.bytecode[k + 1] == 0x01 {
                                    has_crypto_verification = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                
                if !has_crypto_verification {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_inclusion_ordering_manipulation(&self) -> Option<usize> {
        // Pattern: Inclusion list processing without order enforcement
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for loop processing inclusion list
            if self.bytecode[i] == 0x5b { // JUMPDEST (loop start)
                // Check if processing inclusion transactions
                let mut processes_inclusion_list = false;
                
                for j in i+1..i+40.min(self.bytecode.len()) {
                    // Look for transaction execution in loop
                    if self.bytecode[j] == 0xf1 { // CALL (executing tx)
                        processes_inclusion_list = true;
                        break;
                    }
                }
                
                if processes_inclusion_list {
                    // Check for order enforcement (sequential index check)
                    let mut enforces_order = false;
                    
                    for j in i+1..i+45.min(self.bytecode.len()) {
                        // Look for index increment and validation
                        if self.bytecode[j] == 0x01 { // ADD (index++)
                            // Check if index is validated against expected sequence
                            for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 { // EQ (checking order)
                                    enforces_order = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !enforces_order {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_gas_limit_censorship(&self) -> Option<usize> {
        // Pattern: Inclusion transaction execution without gas guarantee
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for transaction execution call
            if self.bytecode[i] == 0xf1 { // CALL
                // Check if gas parameter is sufficient
                let mut guarantees_sufficient_gas = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for GAS opcode (remaining gas)
                    if self.bytecode[j] == 0x5a { // GAS
                        // Check if compared to minimum requirement
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 { // LT (gas >= minimum)
                                guarantees_sufficient_gas = true;
                                break;
                            }
                        }
                    }
                    // Or check for explicit gas allocation
                    if self.bytecode[j] >= 0x60 && self.bytecode[j] <= 0x7f { // PUSH (gas amount)
                        // Check if it's a large value (sufficient gas)
                        if j + 1 < self.bytecode.len() {
                            let gas_value = self.bytecode[j + 1];
                            if gas_value > 50 { // Heuristic: > 50k gas
                                guarantees_sufficient_gas = true;
                            }
                        }
                    }
                }
                
                if !guarantees_sufficient_gas {
                    // Verify this is inclusion list execution
                    for j in i.saturating_sub(40)..i {
                        if self.bytecode[j] == 0x54 { // SLOAD (reading inclusion list)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
