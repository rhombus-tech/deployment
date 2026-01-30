use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOpSimulationDivergenceVulnerability {
    pub location: usize,
    pub vulnerability_type: UserOpDivergenceType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserOpDivergenceType {
    StateDependentValidation,        // Validation depends on mutable state
    TimeDependentValidation,         // Validation depends on block.timestamp
    GasDependentValidation,          // Validation depends on gas price
    NonceManipulation,               // Nonce handling differs between sim/exec
    PaymasterStateDependency,        // Paymaster validation state-dependent
    StorageAccessDivergence,         // Storage reads differ between contexts
}

pub struct UserOpSimulationDivergenceDetector {
    bytecode: Vec<u8>,
}

impl UserOpSimulationDivergenceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UserOpSimulationDivergenceVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_state_dependent_validation() {
            vulnerabilities.push(UserOpSimulationDivergenceVulnerability {
                location: loc,
                vulnerability_type: UserOpDivergenceType::StateDependentValidation,
                severity: "Critical".to_string(),
                description: "validateUserOp reads mutable storage that can change between \
                             simulation and execution. Attacker can front-run to alter validation \
                             outcome, causing bundler to include failing UserOps.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_time_dependent_validation() {
            vulnerabilities.push(UserOpSimulationDivergenceVulnerability {
                location: loc,
                vulnerability_type: UserOpDivergenceType::TimeDependentValidation,
                severity: "High".to_string(),
                description: "Validation uses block.timestamp or block.number, causing divergence \
                             between simulation and execution blocks. Can lead to unexpected \
                             validation failures.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_gas_dependent_validation() {
            vulnerabilities.push(UserOpSimulationDivergenceVulnerability {
                location: loc,
                vulnerability_type: UserOpDivergenceType::GasDependentValidation,
                severity: "Medium".to_string(),
                description: "Validation logic depends on gas price or gas limits, which differ \
                             between simulation and actual execution environment.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_nonce_manipulation() {
            vulnerabilities.push(UserOpSimulationDivergenceVulnerability {
                location: loc,
                vulnerability_type: UserOpDivergenceType::NonceManipulation,
                severity: "High".to_string(),
                description: "Nonce validation can be manipulated between simulation and execution, \
                             allowing replay attacks or simulation bypass.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_paymaster_state_dependency() {
            vulnerabilities.push(UserOpSimulationDivergenceVulnerability {
                location: loc,
                vulnerability_type: UserOpDivergenceType::PaymasterStateDependency,
                severity: "Critical".to_string(),
                description: "Paymaster validation depends on mutable state, allowing attacker to \
                             drain paymaster by causing simulation success but execution failure.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_storage_access_divergence() {
            vulnerabilities.push(UserOpSimulationDivergenceVulnerability {
                location: loc,
                vulnerability_type: UserOpDivergenceType::StorageAccessDivergence,
                severity: "High".to_string(),
                description: "Storage access patterns differ between simulation and execution, \
                             violating ERC-4337 storage access rules.".to_string(),
                confidence: 0.87,
            });
        }

        vulnerabilities
    }

    fn detect_state_dependent_validation(&self) -> Option<usize> {
        // SLOAD in validateUserOp context without proper access control
        // Pattern: PUSH4(validateUserOp selector) followed by SLOAD within 20 instructions
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                // validateUserOp selector: 0x3a871cdd
                if selector == 0x3a871cdd {
                    for j in i..std::cmp::min(i + 20, self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_time_dependent_validation(&self) -> Option<usize> {
        // TIMESTAMP or NUMBER in validation flow
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x42 || self.bytecode[i] == 0x43 { // TIMESTAMP or NUMBER
                // Check if followed by comparison (LT, GT, EQ)
                for j in i + 1..std::cmp::min(i + 10, self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11 | 0x12 | 0x14) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_gas_dependent_validation(&self) -> Option<usize> {
        // GASPRICE in validation logic
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x3a { // GASPRICE
                for j in i + 1..std::cmp::min(i + 8, self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11 | 0x14) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_nonce_manipulation(&self) -> Option<usize> {
        // Nonce increment without proper validation
        // Pattern: SLOAD, PUSH1(1), ADD, SSTORE without proper checks
        for i in 0..self.bytecode.len().saturating_sub(8) {
            if self.bytecode[i] == 0x54 && // SLOAD
               i + 4 < self.bytecode.len() &&
               self.bytecode[i + 1] == 0x60 && // PUSH1
               self.bytecode[i + 2] == 0x01 && // 1
               self.bytecode[i + 3] == 0x01 && // ADD
               self.bytecode[i + 4] == 0x55    // SSTORE
            {
                return Some(i);
            }
        }
        None
    }

    fn detect_paymaster_state_dependency(&self) -> Option<usize> {
        // validatePaymasterUserOp with SLOAD
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                // validatePaymasterUserOp selector: 0xf465c77e
                if selector == 0xf465c77e {
                    for j in i..std::cmp::min(i + 20, self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_storage_access_divergence(&self) -> Option<usize> {
        // Multiple SLOAD operations in validation without proper isolation
        let mut sload_count = 0;
        let mut first_sload = None;
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x54 { // SLOAD
                sload_count += 1;
                if first_sload.is_none() {
                    first_sload = Some(i);
                }
                if sload_count > 3 {
                    return first_sload;
                }
            }
        }
        None
    }
}
