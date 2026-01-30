/// Gas Manipulation Defense Validator
/// Detects gas griefing and manipulation attack vectors
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct GasManipulationDefenseValidator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct GasVulnerability {
    pub vuln_type: GasAttackType,
    pub location: usize,
    pub severity: SecuritySeverity,
    pub description: String,
    pub defense_recommendation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GasAttackType {
    UnboundedLoop,          // DOS via unbounded iteration
    StorageExpansion,       // DOS via excessive storage writes
    CallForwarding,         // Forward all gas to untrusted contract
    ReturnDataBomb,         // Large return data causing OOG
    MemoryExpansion,        // Excessive memory allocation
    ExternalCallGriefing,   // Caller can grief by consuming gas
    GasTokenExploitation,   // Gas token minting/burning manipulation
}

impl GasManipulationDefenseValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn validate_gas_defenses(&self) -> Vec<GasVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for unbounded loops
        vulnerabilities.extend(self.check_unbounded_loops());
        
        // Check for storage expansion attacks
        vulnerabilities.extend(self.check_storage_expansion());
        
        // Check for dangerous call forwarding
        vulnerabilities.extend(self.check_call_forwarding());
        
        // Check for return data bombs
        vulnerabilities.extend(self.check_return_data_bombs());
        
        // Check for memory expansion attacks
        vulnerabilities.extend(self.check_memory_expansion());

        vulnerabilities
    }

    fn check_unbounded_loops(&self) -> Vec<GasVulnerability> {
        let mut vulns = Vec::new();

        // Look for JUMPI (0x57) without clear termination conditions
        for (i, window) in self.bytecode.windows(10).enumerate() {
            if window[0] == 0x57 {
                // Check if there's a decrementing counter (SUB 0x03) nearby
                let has_counter = window.iter().any(|&b| b == 0x03);
                // Check if there's a comparison (LT 0x10) nearby
                let has_comparison = window.iter().any(|&b| b == 0x10);
                
                if !has_counter || !has_comparison {
                    vulns.push(GasVulnerability {
                        vuln_type: GasAttackType::UnboundedLoop,
                        location: i,
                        severity: SecuritySeverity::High,
                        description: "Potentially unbounded loop detected. Can cause DOS via gas exhaustion.".to_string(),
                        defense_recommendation: "Add gas limit checks, use bounded iterations, or implement pagination.".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn check_storage_expansion(&self) -> Vec<GasVulnerability> {
        let mut vulns = Vec::new();

        // Count SSTORE operations - many SSTOREs in a loop is dangerous
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        
        if sstore_count > 10 {
            // Check if SSTOREs are in loops (near JUMPI)
            for (i, window) in self.bytecode.windows(20).enumerate() {
                if window.contains(&0x55) && window.contains(&0x57) {
                    vulns.push(GasVulnerability {
                        vuln_type: GasAttackType::StorageExpansion,
                        location: i,
                        severity: SecuritySeverity::Critical,
                        description: "Storage writes in loop detected. Attacker can trigger massive gas consumption.".to_string(),
                        defense_recommendation: "Use mappings instead of arrays, batch operations, or implement rate limiting.".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn check_call_forwarding(&self) -> Vec<GasVulnerability> {
        let mut vulns = Vec::new();

        // Look for CALL (0xF1) with GAS (0x5A) forwarding
        for (i, window) in self.bytecode.windows(5).enumerate() {
            if window.contains(&0xf1) && window.contains(&0x5a) {
                vulns.push(GasVulnerability {
                    vuln_type: GasAttackType::CallForwarding,
                    location: i,
                    severity: SecuritySeverity::High,
                    description: "Forwarding all available gas to external call. Griefing risk.".to_string(),
                    defense_recommendation: "Set explicit gas limits for external calls: call{gas: X}(...).".to_string(),
                });
            }
        }

        // Check for DELEGATECALL (0xF4) with full gas forwarding
        for (i, window) in self.bytecode.windows(5).enumerate() {
            if window.contains(&0xf4) && window.contains(&0x5a) {
                vulns.push(GasVulnerability {
                    vuln_type: GasAttackType::CallForwarding,
                    location: i,
                    severity: SecuritySeverity::Critical,
                    description: "DELEGATECALL with full gas forwarding. Critical griefing risk.".to_string(),
                    defense_recommendation: "Limit gas or avoid delegatecall to untrusted contracts.".to_string(),
                });
            }
        }

        vulns
    }

    fn check_return_data_bombs(&self) -> Vec<GasVulnerability> {
        let mut vulns = Vec::new();

        // Look for RETURNDATASIZE (0x3D) followed by RETURNDATACOPY (0x3E) without size check
        for (i, window) in self.bytecode.windows(10).enumerate() {
            if window.contains(&0x3d) && window.contains(&0x3e) {
                // Check if there's a size limit check (LT 0x10 or GT 0x11)
                let has_size_check = window.iter().any(|&b| b == 0x10 || b == 0x11);
                
                if !has_size_check {
                    vulns.push(GasVulnerability {
                        vuln_type: GasAttackType::ReturnDataBomb,
                        location: i,
                        severity: SecuritySeverity::High,
                        description: "Unchecked return data copy. Attacker can return huge data causing OOG.".to_string(),
                        defense_recommendation: "Check RETURNDATASIZE and limit copy: require(size <= MAX_SIZE).".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn check_memory_expansion(&self) -> Vec<GasVulnerability> {
        let mut vulns = Vec::new();

        // Look for MSTORE (0x52) or MLOAD (0x51) with potentially large offsets
        // This is simplified - real analysis would track stack values
        for (i, window) in self.bytecode.windows(15).enumerate() {
            if window.contains(&0x52) || window.contains(&0x51) {
                // Check for PUSH followed by large values (>10KB)
                // Looking for PUSH2 (0x61) or higher with large values
                for j in 0..window.len().saturating_sub(3) {
                    if window[j] == 0x61 {
                        let offset = u16::from_be_bytes([window[j + 1], window[j + 2]]);
                        if offset > 10240 { // >10KB
                            vulns.push(GasVulnerability {
                                vuln_type: GasAttackType::MemoryExpansion,
                                location: i + j,
                                severity: SecuritySeverity::Medium,
                                description: format!("Large memory offset detected: {} bytes. Potential gas griefing.", offset),
                                defense_recommendation: "Validate memory offsets and limit expansion.".to_string(),
                            });
                        }
                    }
                }
            }
        }

        vulns
    }

    pub fn calculate_gas_attack_surface(&self) -> f64 {
        let vulns = self.validate_gas_defenses();
        
        let critical = vulns.iter().filter(|v| matches!(v.severity, SecuritySeverity::Critical)).count() as f64;
        let high = vulns.iter().filter(|v| matches!(v.severity, SecuritySeverity::High)).count() as f64;
        let medium = vulns.iter().filter(|v| matches!(v.severity, SecuritySeverity::Medium)).count() as f64;
        
        // Weighted score
        (critical * 10.0) + (high * 5.0) + (medium * 2.0)
    }

    pub fn has_critical_gas_vulnerabilities(&self) -> bool {
        self.validate_gas_defenses()
            .iter()
            .any(|v| matches!(v.severity, SecuritySeverity::Critical))
    }

    pub fn get_gas_defense_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        recommendations.push("Implement gas limits for all external calls".to_string());
        recommendations.push("Use bounded iterations with max iteration count".to_string());
        recommendations.push("Check RETURNDATASIZE before copying return data".to_string());
        recommendations.push("Avoid storage operations in loops".to_string());
        recommendations.push("Implement circuit breakers for expensive operations".to_string());
        recommendations.push("Use pull-over-push pattern for batch operations".to_string());
        
        recommendations
    }

    pub fn estimate_max_gas_consumption(&self) -> u64 {
        let mut gas = 21000u64; // Base transaction cost
        
        // Count expensive operations
        let sstores = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sloads = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let calls = self.bytecode.iter().filter(|&&b| b == 0xf1 || b == 0xf4).count();
        
        // Estimate gas
        gas += (sstores as u64) * 20000;  // SSTORE ~20k gas
        gas += (sloads as u64) * 800;      // SLOAD ~800 gas
        gas += (calls as u64) * 2600;      // CALL ~2600 gas base
        
        gas
    }
}
