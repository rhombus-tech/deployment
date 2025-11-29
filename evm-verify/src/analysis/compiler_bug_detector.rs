/// Compiler Bug Detector
/// Detects known Solidity/Vyper compiler bugs

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerBugVulnerability {
    pub bug_type: CompilerBug,
    pub severity: SecuritySeverity,
    pub description: String,
    pub affected_versions: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompilerBug {
    /// Vyper 0.2.15-0.3.0 reentrancy bug
    VyperReentrancyBug,
    /// Solidity 0.8.13-0.8.16 ABI encoding bug
    SolidityABIBug,
    /// Optimizer bugs in various versions
    OptimizerBug,
    /// Storage array bug
    StorageArrayBug,
    /// Uninitialized function pointer
    UninitializedFunctionPointer,
}

pub struct CompilerBugDetector {
    bytecode: Vec<u8>,
    metadata: Option<String>,
}

impl CompilerBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { 
            bytecode,
            metadata: None,
        }
    }

    pub fn with_metadata(mut self, metadata: String) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CompilerBugVulnerability> {
        let mut vulns = Vec::new();
        vulns.extend(self.detect_vyper_reentrancy_bug());
        vulns.extend(self.detect_solidity_abi_bug());
        vulns.extend(self.detect_storage_array_bug());
        vulns
    }

    /// Detect Vyper 0.2.15-0.3.0 reentrancy bug (Curve exploit)
    fn detect_vyper_reentrancy_bug(&self) -> Vec<CompilerBugVulnerability> {
        let mut vulns = Vec::new();

        // Vyper bug: nonreentrant decorator broken for internal functions
        // Pattern: JUMPDEST without lock check in internal function
        
        // Check metadata for Vyper version
        if let Some(ref metadata) = self.metadata {
            if metadata.contains("vyper") && 
               (metadata.contains("0.2.15") || metadata.contains("0.2.16") || 
                metadata.contains("0.3.0")) {
                
                vulns.push(CompilerBugVulnerability {
                    bug_type: CompilerBug::VyperReentrancyBug,
                    severity: SecuritySeverity::Critical,
                    description: "Contract compiled with Vyper 0.2.15-0.3.0 - nonreentrant decorator bug".to_string(),
                    affected_versions: "Vyper 0.2.15, 0.2.16, 0.3.0".to_string(),
                    exploit_scenario: "Vyper reentrancy bug (Curve exploit $73M):\n\
                        1. @nonreentrant decorator applied to functions\n\
                        2. Compiler bug: lock not checked in internal functions\n\
                        3. External function calls internal function\n\
                        4. Internal function can be reentered\n\
                        5. Drain funds\n\
                        \n\
                        Real exploit: Curve stable pools (July 2023)".to_string(),
                    remediation: "URGENT: Recompile with Vyper 0.3.1+\n\
                        All Vyper 0.2.15-0.3.0 contracts are vulnerable!\n\
                        Upgrade immediately and redeploy.".to_string(),
                });
            }
        }

        // Pattern detection even without metadata
        if self.has_vyper_signature() {
            let has_lock_pattern = self.has_pattern(&[0x54, 0x15]);  // SLOAD + ISZERO (lock check)
            let has_internal_calls = self.count_jumpdests() > 10;
            
            if has_internal_calls && !has_lock_pattern {
                vulns.push(CompilerBugVulnerability {
                    bug_type: CompilerBug::VyperReentrancyBug,
                    severity: SecuritySeverity::Critical,
                    description: "Potential Vyper reentrancy bug pattern detected".to_string(),
                    affected_versions: "Vyper 0.2.15-0.3.0".to_string(),
                    exploit_scenario: "Contract shows Vyper patterns without reentrancy guards".to_string(),
                    remediation: "Verify Vyper version and upgrade if affected".to_string(),
                });
            }
        }

        vulns
    }

    /// Detect Solidity 0.8.13-0.8.16 ABI encoding bug
    fn detect_solidity_abi_bug(&self) -> Vec<CompilerBugVulnerability> {
        let mut vulns = Vec::new();

        if let Some(ref metadata) = self.metadata {
            if metadata.contains("0.8.13") || metadata.contains("0.8.14") || 
               metadata.contains("0.8.15") || metadata.contains("0.8.16") {
                
                vulns.push(CompilerBugVulnerability {
                    bug_type: CompilerBug::SolidityABIBug,
                    severity: SecuritySeverity::High,
                    description: "Contract compiled with Solidity 0.8.13-0.8.16 - ABI encoding bug".to_string(),
                    affected_versions: "Solidity 0.8.13, 0.8.14, 0.8.15, 0.8.16".to_string(),
                    exploit_scenario: "ABI encoding bug:\n\
                        1. Nested arrays or structs in calldata\n\
                        2. Compiler generates incorrect ABI decoder\n\
                        3. Memory corruption possible\n\
                        4. Unexpected behavior or exploits".to_string(),
                    remediation: "Recompile with Solidity 0.8.17+\n\
                        Bug affects complex calldata structures.".to_string(),
                });
            }
        }

        vulns
    }

    /// Detect storage array bug
    fn detect_storage_array_bug(&self) -> Vec<CompilerBugVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Dynamic storage array manipulation
        let has_array_push = self.bytecode.windows(10).any(|w| {
            // Pattern for array.push(): SLOAD + ADD + SSTORE
            w.iter().any(|&b| b == 0x54) && // SLOAD
            w.iter().any(|&b| b == 0x01) && // ADD
            w.iter().any(|&b| b == 0x55)    // SSTORE
        });

        if has_array_push {
            if let Some(ref metadata) = self.metadata {
                if metadata.contains("0.6.") || metadata.contains("0.5.") {
                    vulns.push(CompilerBugVulnerability {
                        bug_type: CompilerBug::StorageArrayBug,
                        severity: SecuritySeverity::Medium,
                        description: "Storage array manipulation in older Solidity version".to_string(),
                        affected_versions: "Solidity <0.7.0".to_string(),
                        exploit_scenario: "Storage array bugs in older compilers can cause:\n\
                            - Array bounds not checked properly\n\
                            - Storage corruption\n\
                            - Unexpected state changes".to_string(),
                        remediation: "Upgrade to Solidity 0.8+".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn has_vyper_signature(&self) -> bool {
        // Vyper uses specific patterns: no function selectors at start
        // Check for Vyper-style dispatch (different from Solidity)
        self.bytecode.len() > 100 && 
        self.bytecode[0] != 0x60 && // Doesn't start with PUSH
        self.count_jumpdests() > 5
    }

    fn has_pattern(&self, pattern: &[u8]) -> bool {
        self.bytecode.windows(pattern.len()).any(|w| w == pattern)
    }

    fn count_jumpdests(&self) -> usize {
        self.bytecode.iter().filter(|&&b| b == 0x5B).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_vyper_bug_from_metadata() {
        let bytecode = vec![0x60, 0x80];
        let detector = CompilerBugDetector::new(bytecode)
            .with_metadata("vyper:0.2.15".to_string());
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.bug_type, CompilerBug::VyperReentrancyBug)));
    }

    #[test]
    fn test_detect_solidity_abi_bug() {
        let bytecode = vec![0x60, 0x80];
        let detector = CompilerBugDetector::new(bytecode)
            .with_metadata("solc:0.8.15".to_string());
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.bug_type, CompilerBug::SolidityABIBug)));
    }
}
